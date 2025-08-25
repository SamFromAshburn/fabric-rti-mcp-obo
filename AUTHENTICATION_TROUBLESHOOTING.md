# Authentication Troubleshooting Guide

## Error Code 53003 - Conditional Access Policy Restriction

You're encountering a common Azure AD issue where conditional access policies are blocking your authentication attempt.

### Immediate Solutions to Try:

#### 1. Contact Your Administrator
The most direct solution is to contact your Azure AD administrator with the following information:
- **Error Code**: 53003
- **Application**: sfrp-obo-fabric-rti-mcp-test
- **App ID**: dbebcc39-fc76-4b5d-b76b-b3007c4953cc
- **Request ID**: 7b71a9db-b440-4b36-8e70-541d42d63a01
- **Correlation ID**: 3ea505a4-7087-403a-bfdf-34d4f82e470e

Ask them to:
- Review conditional access policies for this application
- Add an exception for your user/device if appropriate
- Check if the application requires admin consent
- Verify the application configuration

#### 2. Try Different Authentication Methods

Run the debug script to test different approaches:
```bash
python fabric_rti_mcp\auth\debug_auth.py
```

#### 3. Check Your Environment

Ensure you're authenticating from:
- A managed/compliant device
- An approved network location
- Using an approved authentication method

#### 4. Use a Different Client Application

If available, try using a different Azure AD application registration that may have less restrictive policies.

### Technical Details:

**Error Code 53003** specifically indicates:
- Your authentication was successful
- Your credentials are valid
- However, conditional access policies are blocking access
- This is typically due to device compliance, location, or application-specific restrictions

**Common Conditional Access Restrictions:**
1. **Device Compliance**: Device must be managed by Intune or hybrid joined
2. **Location-based**: Must authenticate from specific IP ranges
3. **Application Controls**: Specific apps may require additional verification
4. **Risk-based**: Authentication may be blocked due to risk assessment

### Alternative Approaches:

1. **Use Managed Identity**: If running in Azure, switch to managed identity authentication
2. **Certificate-based Auth**: Use the certificate-based authentication flow already implemented in the codebase
3. **Different Scopes**: Try with basic Microsoft Graph scopes first, then request additional permissions

### Debugging Commands:

```bash
# Check device compliance (if on domain-joined machine)
dsregcmd /status

# Check current user context
whoami /all

# Test basic Azure CLI authentication
az login
az account show
```

### Next Steps:

1. Run the debug script to gather more information
2. Document the exact error details and environment
3. Work with your Azure AD administrator to resolve the conditional access restriction
4. Consider implementing certificate-based authentication for production use
