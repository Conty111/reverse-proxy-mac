package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"reverse-proxy-mac/src/domain/logger"
)

type LDAPClient interface {
	SearchUser(ctx context.Context, username string) (*UserInfo, error)
}

type UserInfo struct {
	DN                 string
	Username           string
	DisplayName        string
	Email              string
	GivenName          string
	Surname            string
	Department         string
	Title              string
	TelephoneNumber    string
	Mobile             string
	Company            string
	StreetAddress      string
	City               string
	State              string
	PostalCode         string
	Country            string
	Manager            string
	MemberOf           []string
	AccountExpires     string
	LastLogon          string
	WhenCreated        string
	WhenChanged        string
	UserAccountControl string
	Description        string
	Office             string
	EmployeeID         string
	EmployeeNumber     string
	HomeDirectory      string
	HomeDrive          string
	ScriptPath         string
	ProfilePath        string
}

type Client struct {
	host              string
	port              int
	baseDN            string
	userFilter        string
	useTLS            bool
	useKerberos       bool
	keytabPath        string
	kerberosPrincipal string
	kerberosRealm     string
	logger            logger.Logger
	krb5Client        *client.Client
}

func NewClient(host string, port int, baseDN, userFilter string, useTLS, useKerberos bool, keytabPath, kerberosPrincipal, kerberosRealm string, log logger.Logger) (*Client, error) {
	c := &Client{
		host:              host,
		port:              port,
		baseDN:            baseDN,
		userFilter:        userFilter,
		useTLS:            useTLS,
		useKerberos:       useKerberos,
		keytabPath:        keytabPath,
		kerberosPrincipal: kerberosPrincipal,
		kerberosRealm:     kerberosRealm,
		logger:            log,
	}

	if useKerberos && keytabPath != "" {
		if err := c.initKerberos(); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *Client) initKerberos() error {
	kt, err := keytab.Load(c.keytabPath)
	if err != nil {
		return fmt.Errorf("failed to load keytab: %w", err)
	}

	krb5conf := config.New()
	krb5conf.LibDefaults.DefaultRealm = c.kerberosRealm
	krb5conf.Realms = []config.Realm{
		{
			Realm: c.kerberosRealm,
			KDC:   []string{c.host + ":88"},
		},
	}

	cl := client.NewWithKeytab(c.kerberosPrincipal, c.kerberosRealm, kt, krb5conf, client.DisablePAFXFAST(true))

	if err := cl.Login(); err != nil {
		return fmt.Errorf("failed to login with keytab: %w", err)
	}

	c.krb5Client = cl
	return nil
}

func (c *Client) Connect(ctx context.Context) (*ldap.Conn, error) {
	var ldapURL string
	if c.useTLS {
		ldapURL = fmt.Sprintf("ldaps://%s:%d", c.host, c.port)
	} else {
		ldapURL = fmt.Sprintf("ldap://%s:%d", c.host, c.port)
	}

	conn, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(&tls.Config{
		ServerName:         c.host,
		InsecureSkipVerify: true,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	if !c.useTLS {
		err = conn.StartTLS(&tls.Config{
			ServerName:         c.host,
			InsecureSkipVerify: true,
		})
		if err != nil {
			c.logger.Debug(ctx, "StartTLS upgrade failed, continuing without TLS", map[string]interface{}{"error": err.Error()})
		}
	}

	if c.useKerberos && c.krb5Client != nil {
		if err := c.bindWithGSSAPI(ctx, conn); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to bind to LDAP with GSSAPI: %w", err)
		}
	}

	return conn, nil
}

type gssapiClientImpl struct {
	client *client.Client
	host   string
	logger logger.Logger
	ctx    context.Context
}

func (g *gssapiClientImpl) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	ldapService := fmt.Sprintf("ldap/%s", g.host)
	spnegoClient := spnego.SPNEGOClient(g.client, ldapService)

	token, err := spnegoClient.InitSecContext()
	if err != nil {
		return nil, false, fmt.Errorf("failed to initialize security context: %w", err)
	}

	tokenBytes, err := token.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal token: %w", err)
	}

	return tokenBytes, true, nil
}

func (g *gssapiClientImpl) InitSecContextWithOptions(target string, input []byte, options []int) ([]byte, bool, error) {
	return g.InitSecContext(target, input)
}

func (g *gssapiClientImpl) NegotiateSaslAuth(input []byte, authzID string) ([]byte, error) {
	return nil, nil
}

func (g *gssapiClientImpl) DeleteSecContext() error {
	return nil
}

func (c *Client) bindWithGSSAPI(ctx context.Context, conn *ldap.Conn) error {
	gssClient := &gssapiClientImpl{
		client: c.krb5Client,
		host:   c.host,
		logger: c.logger,
		ctx:    ctx,
	}

	targetName := fmt.Sprintf("ldap@%s", c.host)

	if err := conn.GSSAPIBind(gssClient, targetName, ""); err != nil {
		return fmt.Errorf("GSSAPI bind failed: %w", err)
	}

	return nil
}

func (c *Client) SearchUser(ctx context.Context, username string) (*UserInfo, error) {
	conn, err := c.Connect(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if idx := strings.Index(username, "@"); idx != -1 {
		username = username[:idx]
	}

	filter := fmt.Sprintf(c.userFilter, ldap.EscapeFilter(username))

	attributes := []string{
		"distinguishedName", "sAMAccountName", "displayName", "mail", "givenName", "sn",
		"department", "title", "telephoneNumber", "mobile", "company", "streetAddress",
		"l", "st", "postalCode", "co", "manager", "memberOf", "accountExpires", "lastLogon",
		"whenCreated", "whenChanged", "userAccountControl", "description",
		"physicalDeliveryOfficeName", "employeeID", "employeeNumber", "homeDirectory",
		"homeDrive", "scriptPath", "profilePath",
	}

	searchRequest := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found in LDAP: %s", username)
	}

	if len(result.Entries) > 1 {
		c.logger.Warn(ctx, "Multiple LDAP entries found for user", map[string]interface{}{
			"username": username,
			"count":    len(result.Entries),
		})
	}

	entry := result.Entries[0]
	return &UserInfo{
		DN:                 entry.DN,
		Username:           entry.GetAttributeValue("sAMAccountName"),
		DisplayName:        entry.GetAttributeValue("displayName"),
		Email:              entry.GetAttributeValue("mail"),
		GivenName:          entry.GetAttributeValue("givenName"),
		Surname:            entry.GetAttributeValue("sn"),
		Department:         entry.GetAttributeValue("department"),
		Title:              entry.GetAttributeValue("title"),
		TelephoneNumber:    entry.GetAttributeValue("telephoneNumber"),
		Mobile:             entry.GetAttributeValue("mobile"),
		Company:            entry.GetAttributeValue("company"),
		StreetAddress:      entry.GetAttributeValue("streetAddress"),
		City:               entry.GetAttributeValue("l"),
		State:              entry.GetAttributeValue("st"),
		PostalCode:         entry.GetAttributeValue("postalCode"),
		Country:            entry.GetAttributeValue("co"),
		Manager:            entry.GetAttributeValue("manager"),
		MemberOf:           entry.GetAttributeValues("memberOf"),
		AccountExpires:     entry.GetAttributeValue("accountExpires"),
		LastLogon:          entry.GetAttributeValue("lastLogon"),
		WhenCreated:        entry.GetAttributeValue("whenCreated"),
		WhenChanged:        entry.GetAttributeValue("whenChanged"),
		UserAccountControl: entry.GetAttributeValue("userAccountControl"),
		Description:        entry.GetAttributeValue("description"),
		Office:             entry.GetAttributeValue("physicalDeliveryOfficeName"),
		EmployeeID:         entry.GetAttributeValue("employeeID"),
		EmployeeNumber:     entry.GetAttributeValue("employeeNumber"),
		HomeDirectory:      entry.GetAttributeValue("homeDirectory"),
		HomeDrive:          entry.GetAttributeValue("homeDrive"),
		ScriptPath:         entry.GetAttributeValue("scriptPath"),
		ProfilePath:        entry.GetAttributeValue("profilePath"),
	}, nil
}
