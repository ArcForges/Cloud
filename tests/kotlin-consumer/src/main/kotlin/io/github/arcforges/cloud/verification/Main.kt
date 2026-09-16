// SPDX-License-Identifier: AGPL-3.0-only
package io.github.arcforges.cloud.verification

import com.connectrpc.Code
import com.connectrpc.ConnectException
import com.connectrpc.ProtocolClientConfig
import com.connectrpc.extensions.GoogleJavaLiteProtobufStrategy
import com.connectrpc.getOrThrow
import com.connectrpc.impl.ProtocolClient
import com.connectrpc.okhttp.ConnectOkHttpClient
import com.connectrpc.protocols.NetworkProtocol
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import com.sun.net.httpserver.HttpServer
import io.github.arcforges.contracts.hello.v1.HelloServiceClient
import io.github.arcforges.contracts.hello.v1.sayHelloRequest
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.Properties
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Request

private const val method = "/arcforges.hello.v1.HelloService/SayHello"

private fun sdk(http: OkHttpClient, base: String, timeout: Duration) = HelloServiceClient(
    ProtocolClient(
        httpClient = ConnectOkHttpClient(http),
        config = ProtocolClientConfig(
            host = base,
            serializationStrategy = GoogleJavaLiteProtobufStrategy(),
            networkProtocol = NetworkProtocol.GRPC_WEB,
            ioCoroutineContext = Dispatchers.IO,
            timeoutOracle = { timeout },
        ),
    ),
)

private fun builder() = OkHttpClient.Builder()
    .callTimeout(15, TimeUnit.SECONDS)
    .retryOnConnectionFailure(false)
    .followRedirects(false)
    .followSslRedirects(false)

private fun close(http: OkHttpClient) {
    http.dispatcher.executorService.shutdownNow()
    http.connectionPool.evictAll()
}

private suspend fun expectCode(code: Code, call: suspend () -> Unit) {
    try {
        call()
        error("RPC unexpectedly succeeded; expected $code")
    } catch (failure: ConnectException) {
        check(failure.code == code) { "Expected $code, received ${failure.code}: ${failure.message}" }
    }
}

private fun terminalStatus(bytes: ByteArray, header: String?): Int {
    if (bytes.isEmpty() && header != null) return header.toInt()
    var offset = 0
    while (offset < bytes.size) {
        check(offset + 5 <= bytes.size) { "Truncated gRPC-Web envelope" }
        val flag = bytes[offset].toInt() and 255
        val length = ByteBuffer.wrap(bytes, offset + 1, 4).int
        check(length >= 0 && length <= bytes.size - offset - 5)
        offset += 5
        if (flag == 128) {
            check(offset + length == bytes.size) { "Trailers must terminate the unary response" }
            val trailers = String(bytes, offset, length, Charsets.US_ASCII)
            return Regex("(?m)^grpc-status: ?([0-9]+)\\r?$").find(trailers)!!.groupValues[1].toInt()
        }
        check(flag == 0) { "Unexpected compressed response" }
        offset += length
    }
    error("Response omitted the terminal gRPC status")
}

// Local fault injection only: no production delay endpoint and no claim of server evidence.
private suspend fun verifyClientDeadline() {
    for (partialResponse in listOf(false, true)) {
        val calls = AtomicInteger()
        val release = CountDownLatch(1)
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext(method) { exchange ->
            try {
                exchange.requestBody.readAllBytes()
                calls.incrementAndGet()
                if (partialResponse) {
                    exchange.responseHeaders.add("Content-Type", "application/grpc-web+proto")
                    exchange.sendResponseHeaders(200, 0)
                    exchange.responseBody.write(byteArrayOf(0))
                    exchange.responseBody.flush()
                }
                release.await(5, TimeUnit.SECONDS)
            } finally {
                exchange.close()
            }
        }
        server.start()
        val http = builder().build()
        try {
            val client = sdk(http, "http://127.0.0.1:${server.address.port}", 500.milliseconds)
            withTimeout(3.seconds) {
                expectCode(Code.DEADLINE_EXCEEDED) {
                    client.sayHello(sayHelloRequest { name = "Deadline fixture" }).getOrThrow()
                }
            }
            check(calls.get() == 1) { "Deadline must not replay the RPC" }
        } finally {
            release.countDown()
            server.stop(0)
            close(http)
        }
    }
    println("Kotlin local fault fixture: deadline before headers and during body, no retry, passed.")
}

private suspend fun verifyEndpoint(args: Array<String>) {
    require(args.size == 4) { "Expected base URL, source revision, container|worker, evidence path" }
    val (base, revision, boundary, output) = args.toList()
    require(!base.endsWith("/"))
    require(boundary in listOf("container", "worker"))
    val worker = boundary == "worker"
    val uri = java.net.URI(base)
    require(uri.rawQuery == null && uri.rawFragment == null && uri.userInfo == null)
    require(uri.path == if (worker) "/api" else "") { "Expected exactly one /api prefix for Worker" }
    require(uri.scheme == "https" || (uri.scheme == "http" && uri.host == "127.0.0.1"))
    val wire = Collections.synchronizedList(mutableListOf<Map<String, Any>>())
    val http = builder().addInterceptor { chain ->
        val request = chain.request()
        if (request.method != "POST") return@addInterceptor chain.proceed(request)
        check(request.url.encodedPath == uri.path + method)
        check(request.body?.contentType().toString() == "application/grpc-web+proto")
        check(request.header("grpc-timeout")?.matches(Regex("[0-9]{1,8}[HMSmun]")) == true)
        val response = chain.proceed(request)
        check(response.code == 200) { "Unexpected HTTP ${response.code}" }
        val contentType = response.header("Content-Type")!!.substringBefore(';').lowercase()
        check(contentType in listOf("application/grpc-web", "application/grpc-web+proto"))
        if (worker) check(response.header("x-arcforges-worker-revision") == revision)
        wire.add(mapOf(
            "path" to request.url.encodedPath,
            "requestContentType" to request.body!!.contentType().toString(),
            "requestTimeout" to request.header("grpc-timeout")!!,
            "responseContentType" to contentType,
            "httpStatus" to response.code,
            "grpcStatus" to terminalStatus(response.peekBody(8192).bytes(), response.header("grpc-status")),
        ))
        response
    }.build()
    try {
        withTimeout(60.seconds) {
            http.newCall(Request.Builder().url("$base/healthz").build()).execute().use { response ->
                check(response.code == 200)
                val health = JsonParser.parseString(response.body.string()).asJsonObject
                check(health["service"].asString == "arcforges-cloud")
                check(health["revision"].asString == revision)
                check(health["nativeAot"].asBoolean) { "JIT host does not satisfy this check" }
                if (worker) check(response.header("x-arcforges-worker-revision") == revision)
            }
            val client = sdk(http, base, 5.seconds)
            for (name in listOf("ArcForges", "世界 👋", " \t ", "x".repeat(256))) {
                check(client.sayHello(sayHelloRequest { this.name = name }).getOrThrow().message == "Hello, $name!")
            }
            expectCode(Code.INVALID_ARGUMENT) {
                client.sayHello(sayHelloRequest { name = "" }).getOrThrow()
            }
            expectCode(Code.RESOURCE_EXHAUSTED) {
                client.sayHello(sayHelloRequest { name = "x".repeat(257) }).getOrThrow()
            }
        }
        check(wire.map { it["grpcStatus"] } == listOf(0, 0, 0, 0, 3, 8))
        if (worker) {
            // A duplicated base prefix is a transport error, never a protobuf greeting.
            val wrongPathHttp = builder().addInterceptor { chain ->
                chain.proceed(chain.request()).also { check(it.code == 404) }
            }.build()
            try {
                expectCode(Code.UNIMPLEMENTED) {
                    sdk(wrongPathHttp, "$base/api", 5.seconds)
                        .sayHello(sayHelloRequest { name = "Wrong prefix" }).getOrThrow()
                }
            } finally {
                close(wrongPathHttp)
            }
        }
        val metadata = Properties().apply {
            HelloServiceClient::class.java.classLoader.getResourceAsStream("verification.properties")!!.use { load(it) }
        }
        val evidence = mapOf(
            "client" to "io.github.arcforges:contracts-connect-client:${metadata.getProperty("contractsVersion")}",
            "transport" to "binary gRPC-Web",
            "baseUrl" to base,
            "revision" to revision,
            "boundary" to boundary,
            "nativeAot" to true,
            "wrongPrefixHttp404" to worker,
            "wire" to wire,
        )
        val file = Path.of(output).toAbsolutePath()
        Files.createDirectories(file.parent)
        Files.writeString(file, GsonBuilder().setPrettyPrinting().create().toJson(evidence) + "\n")
        println("Published Kotlin client: $base at $revision, six real RPCs and trailers verified.")
    } finally {
        close(http)
    }
}

fun main(args: Array<String>) = runBlocking {
    if (args.contentEquals(arrayOf("--self-test"))) verifyClientDeadline() else verifyEndpoint(args)
}
