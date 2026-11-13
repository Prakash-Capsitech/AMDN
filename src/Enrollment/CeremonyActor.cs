namespace AMDN.Enrollment;

// Trusted server projection, NOT an authentication API. Application use must go
// through EnrollmentPrincipalMapper; raw construction is for internal/test code.
internal sealed record CeremonyActor(Guid TenantId, string Issuer, string Subject, string ClientId,
    string Origin, Guid ConfigurationId, string Scope, string Acr, DateTime AuthTime, DateTime TokenExpiry);
