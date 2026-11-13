namespace AMDN.Enrollment;

// Trusted server projection, NOT an authentication API. Only a future validated
// principal bridge may construct this for application use. No host registers it.
internal sealed record CeremonyActor(Guid TenantId, string Issuer, string Subject, string ClientId,
    string Origin, Guid ConfigurationId, string Scope, string Acr, DateTime AuthTime, DateTime TokenExpiry);
