package msad

const (
	ClassDomainDNS          = "domainDNS"
	ClassContainer          = "container"
	ClassOrganizationalUnit = "organizationalUnit"
	ClassComputer           = "computer"
	ClassContact            = "contact"
	ClassGroup              = "group"
	ClassUser               = "user"
)

const (
	CategoryOrganizationalUnit = "OrganizationalUnit"
	CategoryContainer          = "Container"
	CategoryComputer           = "Computer"
	CategoryPerson             = "Person"
	CategoryGroup              = "Group"
)

const (
	UserAccountEnable  = "66048"
	UserAccountDisable = "66050"
)

const (
	SCRIPT                                 = 0x00000001 // The logon script is executed.
	ACCOUNTDISABLE                         = 0x00000002 // The user account is disabled.
	HOMEDIR_REQUIRED                       = 0x00000008 // The home directory is required.
	LOCKOUT                                = 0x00000010 // The account is currently locked out.
	PASSWD_NOTREQD                         = 0x00000020 // No password is required.
	PASSWD_CANT_CHANGE                     = 0x00000040 // The user cannot change the password.
	ENCRYPTED_TEXT_PASSWORD_ALLOWED        = 0x00000080 // The user can send an encrypted password.
	TEMP_DUPLICATE_ACCOUNT                 = 0x00000100 // This is an account for users whose primary account is in another domain.
	NORMAL_ACCOUNT                         = 0x00000200 // This is a default account type that represents a typical user.
	INTERDOMAIN_TRUST_ACCOUNT              = 0x00000800 // This is a permit to trust account for a system domain that trusts other domains.
	WORKSTATION_TRUST_ACCOUNT              = 0x00001000 // This is a computer account for a computer that is a member of this domain.
	SERVER_TRUST_ACCOUNT                   = 0x00002000 // This is a computer account for a system backup domain controller that is a member of this domain.
	Unused1                                = 0x00004000 // Not used.
	Unused2                                = 0x00008000 // Not used.
	DONT_EXPIRE_PASSWD                     = 0x00010000 // The password for this account will never expire.
	MNS_LOGON_ACCOUNT                      = 0x00020000 // This is an MNS logon account.
	SMARTCARD_REQUIRED                     = 0x00040000 // The user must log on using a smart card.
	TRUSTED_FOR_DELEGATION                 = 0x00080000 // The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation.
	NOT_DELEGATED                          = 0x00100000 // The security context of the user will not be delegated to a service even if the service account is set as trusted for Kerberos delegation.
	USE_DES_KEY_ONLY                       = 0x00200000 // Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
	DONT_REQUIRE_PREAUTH                   = 0x00400000 // This account does not require Kerberos pre-authentication for logon.
	PASSWORD_EXPIRED                       = 0x00800000 // The user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute and the domain policy.
	TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000 // The account is enabled for delegation.
	USE_AES_KEYS                           = 0x08000000
)
