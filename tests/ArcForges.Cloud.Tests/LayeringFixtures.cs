// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.CloudInternal.Storage.V1;

#pragma warning disable CA1812, CA1822, IDE0051, IDE0052, CS0169, CS0649
namespace LayeringFixtures
{
    namespace Good
    {
        namespace Domain
        {
            public sealed class Entity
            {
                public string Name { get; init; } = "";
            }
        }

        namespace Application
        {
            public sealed class UseCase(Domain.Entity entity)
            {
                public Domain.Entity Entity { get; } = entity;
            }
        }

        namespace Infrastructure
        {
            public sealed class Repository(Application.UseCase useCase, D1Scalar? wire)
            {
                public Application.UseCase UseCase { get; } = useCase;

                public D1Scalar? Wire { get; } = wire;
            }
        }
    }

    namespace Bad
    {
        namespace Infrastructure
        {
            public class Store;
        }

        namespace Application
        {
            public sealed class ApplicationWithInfrastructureProperty
            {
                public Infrastructure.Store? Store { get; init; }
            }

            public sealed class ApplicationWithWireList
            {
                public List<D1Scalar> Items { get; init; } = [];
            }

            public sealed class Port;
        }

        namespace Domain
        {
            public sealed class DomainWithInfrastructureField
            {
                private Infrastructure.Store? store;
            }

            public sealed class DomainWithApplicationParameter
            {
                public void Run(Application.Port port)
                {
                }
            }

            public sealed class DomainWithWireType
            {
                public D1Scalar? Value { get; init; }
            }

            public sealed class DomainInheritingInfrastructure : Infrastructure.Store;
        }
    }
}
