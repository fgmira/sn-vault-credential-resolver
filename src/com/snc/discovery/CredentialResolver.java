package com.snc.discovery;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.AuthResponse;
import com.bettercloud.vault.response.LogicalResponse;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.snc.automation_common.integration.creds.IExternalCredential;
import com.snc.core_automation_common.logging.Logger;
import com.snc.core_automation_common.logging.LoggerFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom External Credential Resolver for HashiCorp credential vault.
 * Use Vault Java Driver a community written zero-dependency
 * Java client from <a href="https://bettercloud.github.io/vault-java-driver/">...</a>
 */
public class CredentialResolver implements IExternalCredential{

	public static final String HASHICORP_VAULT_ADDRESS_PROPERTY = "ext.cred.hashicorp.vault.address";
	public static final String HASHICORP_VAULT_VALID_SSL_PROPERTY = "ext.cred.hashicorp.vault.valid.ssl";
	public static final String HASHICORP_VAULT_LOGIN_TYPE_PROPERTY = "ext.cred.hashicorp.vault.login.type";
	public static final String HASHICORP_VAULT_LOGIN_TOKEN_PROPERTY = "ext.cred.hashicorp.vault.token";
	public static final String HASHICORP_VAULT_LOGIN_AWS_ROLE_NAME_PROPERTY =
			"ext.cred.hashicorp.vault.login.aws_role_name";
	public static final String HASHICORP_VAULT_LOGIN_AWS_ROLE_ARN_PROPERTY =
			"ext.cred.hashicorp.vault.login.aws_role_arn";
	public static final String HASHICORP_VAULT_LOGIN_AWS_ACCOUNT_ID_PROPERTY =
			"ext.cred.hashicorp.vault.login.aws_account_id";

	public static final String HASHICORP_VAULT_LOGIN_AWS_REGION_PROPERTY = "ext.cred.hashicorp.vault.login.aws_region";
	public static final String HASHICORP_VAULT_LOGIN_USER_PROPERTY = "ext.cred.hashicorp.vault.login.user";
	public static final String HASHICORP_VAULT_LOGIN_PASSWORD_PROPERTY = "ext.cred.hashicorp.vault.login.password";

	//Remove hard-coded values and read them from config.xml
	private String hashicorpVaultAddress = "";
	private String hashicorpVaultValidSSL = "";
	private String hashicorpVaultLoginType = "";
	private String hashicorpVaultToken = "";
	private String hashicorpVaultAwsRoleName = "";
	private String hashicorpVaultAwsRoleArn = "";
	private String hashicorpVaultAwsAccountId = "";
	private Region hashicorpVaultAwsRegion = null;
	private String hashicorpVaultUser = "";
	private String hashicorpVaultPassword = "";

	// Logger object to log messages in agent.log
	private static final Logger fLogger = LoggerFactory.getLogger(CredentialResolver.class);

	public CredentialResolver() {
	}
	
	/**
	 * Config method with preloaded config parameters from config.xml.
	 * @param configMap - contains config parameters with prefix "ext.cred" only.
	 */
	@Override
	public void config(Map<String, String> configMap) {
		//Note: To load config parameters from MID config.xml if not available in configMap.
		//propValue = Config.get().getProperty("<Parameter Name>")

		// Load HashiCorp Vault config parameters
		hashicorpVaultAddress = configMap.get(HASHICORP_VAULT_ADDRESS_PROPERTY);
		fLogger.info("[Vault] INFO - CredentialResolver: " +
				HASHICORP_VAULT_ADDRESS_PROPERTY + " = " + hashicorpVaultAddress);
		if(isNullOrEmpty(hashicorpVaultAddress)) {
			fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_ADDRESS_PROPERTY + " not set!");
			throw new RuntimeException("CredentialResolver: Property " + HASHICORP_VAULT_ADDRESS_PROPERTY
					+ " not set in config.xml!");
		}
		if (!hashicorpVaultAddress.matches("https?://.*")){
			fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_ADDRESS_PROPERTY +
					" = " + hashicorpVaultAddress + " is not a valid URL. Please set it to a valid URL.");
			throw new RuntimeException("CredentialResolver: Property " + HASHICORP_VAULT_ADDRESS_PROPERTY +
					" = " + hashicorpVaultAddress + " is not a valid URL. Please set it to a valid URL.");
		}

		hashicorpVaultValidSSL = configMap.get(HASHICORP_VAULT_VALID_SSL_PROPERTY);
		fLogger.info("[Vault] INFO - CredentialResolver: " +
				HASHICORP_VAULT_VALID_SSL_PROPERTY + " = " + hashicorpVaultValidSSL);
		if(isNullOrEmpty(hashicorpVaultValidSSL)) {
			fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_VALID_SSL_PROPERTY +
					" not set! Please set it to true or false.");
			throw new RuntimeException("CredentialResolver: Property " + HASHICORP_VAULT_VALID_SSL_PROPERTY +
					" not set in config.xml!");
		}
		if (!hashicorpVaultValidSSL.equals("true") && !hashicorpVaultValidSSL.equals("false")){
			fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_VALID_SSL_PROPERTY +
					" = " + hashicorpVaultValidSSL + " is not a valid value. Please set it to true or false.");
			throw new RuntimeException("CredentialResolver: Property " + HASHICORP_VAULT_VALID_SSL_PROPERTY +
					" = " + hashicorpVaultValidSSL + " is not a valid value. Please set it to true or false.");
		}

		hashicorpVaultLoginType = configMap.get(HASHICORP_VAULT_LOGIN_TYPE_PROPERTY);
		fLogger.info("[Vault] INFO - CredentialResolver: " +
				HASHICORP_VAULT_LOGIN_TYPE_PROPERTY + " = " + hashicorpVaultLoginType);
		if(isNullOrEmpty(hashicorpVaultLoginType)) {
			fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_LOGIN_TYPE_PROPERTY +
					" not set! Please set it to one of the following values: AWS_ROLE, USER_PASS, TOKEN.");
			throw new RuntimeException("CredentialResolver: Property " + HASHICORP_VAULT_LOGIN_TYPE_PROPERTY +
					" not set in config.xml!");
		}
		switch (hashicorpVaultLoginType){
			case "AWS_ROLE":
				hashicorpVaultAwsRoleName = configMap.get(HASHICORP_VAULT_LOGIN_AWS_ROLE_NAME_PROPERTY);
				if(isNullOrEmpty(hashicorpVaultAwsRoleName)) {
					fLogger.error("[Vault] ERROR - CredentialResolver: "
							+ HASHICORP_VAULT_LOGIN_AWS_ROLE_NAME_PROPERTY +
							" not set! This is mandatory for AWS_ROLE login type.");
					throw new RuntimeException("CredentialResolver: Property " +
							HASHICORP_VAULT_LOGIN_AWS_ROLE_NAME_PROPERTY + " not set in config.xml!");
				}

				String awsRegion= configMap.get(HASHICORP_VAULT_LOGIN_AWS_REGION_PROPERTY);
				if(isNullOrEmpty(awsRegion)) {
					fLogger.error("[Vault] ERROR - CredentialResolver: "
							+ HASHICORP_VAULT_LOGIN_AWS_REGION_PROPERTY +
							" not set! This is mandatory for AWS_ROLE login type.");
					throw new RuntimeException("CredentialResolver: Property " +
							HASHICORP_VAULT_LOGIN_AWS_REGION_PROPERTY + " not set in config.xml!");
				}
				boolean isAwsRegionValid = true;
				for (Region region: Region.regions()){
					if (region.id().equalsIgnoreCase(awsRegion)){
						isAwsRegionValid = true;
						hashicorpVaultAwsRegion = region;
						break;
					}
					else {
						isAwsRegionValid = false;
					}
				}
				if(!isAwsRegionValid){
					fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_LOGIN_AWS_REGION_PROPERTY +
							" = " + awsRegion + " is not a valid AWS region. Please set it to one of the following " +
							"values: " + Region.regions());
					throw new RuntimeException("CredentialResolver: Property " +
							HASHICORP_VAULT_LOGIN_AWS_REGION_PROPERTY + " = " + awsRegion +
							" is not a valid AWS region. Please set it to one of the following values: " +
							Region.regions().toString());
				}

				hashicorpVaultAwsAccountId = configMap.get(HASHICORP_VAULT_LOGIN_AWS_ACCOUNT_ID_PROPERTY);
				if(isNullOrEmpty(hashicorpVaultAwsAccountId)) {
					fLogger.error("[Vault] ERROR - CredentialResolver: "
							+ HASHICORP_VAULT_LOGIN_AWS_ACCOUNT_ID_PROPERTY +
							" not set! This is mandatory for AWS_ROLE login type.");
					throw new RuntimeException("CredentialResolver: Property " +
							HASHICORP_VAULT_LOGIN_AWS_ACCOUNT_ID_PROPERTY + " not set in config.xml!");
				}
				if (hashicorpVaultAwsAccountId.matches("\\d{12}")){
					fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_LOGIN_AWS_ACCOUNT_ID_PROPERTY +
							" = " + hashicorpVaultAwsAccountId + " is not a valid AWS account ID. Please set it to " +
							"12 digit AWS account ID.");
					throw new RuntimeException("CredentialResolver: Property " +
							HASHICORP_VAULT_LOGIN_AWS_ACCOUNT_ID_PROPERTY + " = " + hashicorpVaultAwsAccountId +
							" is not a valid AWS account ID. Please set it to 12 digit AWS account ID.");
				}

				hashicorpVaultAwsRoleArn = configMap.get(HASHICORP_VAULT_LOGIN_AWS_ROLE_ARN_PROPERTY);
				if (isNullOrEmpty(hashicorpVaultAwsRoleArn)) {
					fLogger.error("[Vault] ERROR - CredentialResolver: "
							+ HASHICORP_VAULT_LOGIN_AWS_ROLE_ARN_PROPERTY +
							" not set! This is mandatory for AWS_ROLE login type.");
					throw new RuntimeException("CredentialResolver: Property " +
							HASHICORP_VAULT_LOGIN_AWS_ROLE_ARN_PROPERTY + " not set in config.xml!");
				}
				if (!hashicorpVaultAwsRoleArn.matches("arn:aws:iam::\\d{12}:role/.*")){
					fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_LOGIN_AWS_ROLE_ARN_PROPERTY +
							" = " + hashicorpVaultAwsRoleArn + " is not a valid AWS role ARN. Please set it to " +
							"ARN of the AWS role.");
					throw new RuntimeException("CredentialResolver: Property " +
							HASHICORP_VAULT_LOGIN_AWS_ROLE_ARN_PROPERTY + " = " + hashicorpVaultAwsRoleArn +
							" is not a valid AWS role ARN. Please set it to ARN of the AWS role.");
				}

				fLogger.info("[Vault] INFO - CredentialResolver: " +
						HASHICORP_VAULT_LOGIN_AWS_ROLE_NAME_PROPERTY + " = " + hashicorpVaultAwsRoleName);
				fLogger.info("[Vault] INFO - CredentialResolver: " +
						HASHICORP_VAULT_LOGIN_AWS_REGION_PROPERTY + " = " + awsRegion);
				fLogger.info("[Vault] INFO - CredentialResolver: " +
						HASHICORP_VAULT_LOGIN_AWS_ACCOUNT_ID_PROPERTY + " = " + hashicorpVaultAwsAccountId);
				fLogger.info("[Vault] INFO - CredentialResolver: " +
						HASHICORP_VAULT_LOGIN_AWS_ROLE_ARN_PROPERTY + " = " + hashicorpVaultAwsRoleArn);

				break;
			case "USER_PASS":
				fLogger.warn("[Vault] WARNING - CredentialResolver: " + HASHICORP_VAULT_LOGIN_TYPE_PROPERTY +
						" = USER_PASS is not recommended for production use. Please use TOKEN or AWS_ROLE login type.");
				hashicorpVaultUser = configMap.get(HASHICORP_VAULT_LOGIN_USER_PROPERTY);
				if(isNullOrEmpty(hashicorpVaultUser)) {
					fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_LOGIN_USER_PROPERTY +
							" not set! This is mandatory for USER_PASS login type.");
					throw new RuntimeException("CredentialResolver: Property " + HASHICORP_VAULT_LOGIN_USER_PROPERTY +
							" not set in config.xml!");
				}
				hashicorpVaultPassword = configMap.get(HASHICORP_VAULT_LOGIN_PASSWORD_PROPERTY);
				if(isNullOrEmpty(hashicorpVaultPassword)) {
					fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_LOGIN_PASSWORD_PROPERTY +
							" not set! This is mandatory for USER_PASS login type.");
					throw new RuntimeException("CredentialResolver: Property " +
							HASHICORP_VAULT_LOGIN_PASSWORD_PROPERTY + " not set in config.xml!");
				}
				break;
			case "TOKEN":
				hashicorpVaultToken = configMap.get(HASHICORP_VAULT_LOGIN_TOKEN_PROPERTY);
				if(isNullOrEmpty(hashicorpVaultToken)) {
					fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_LOGIN_TOKEN_PROPERTY +
							" not set! This is mandatory for TOKEN login type.");
					throw new RuntimeException("CredentialResolver: Property " + HASHICORP_VAULT_LOGIN_TOKEN_PROPERTY +
							" not set in config.xml!");
				}
				break;
			default:
				fLogger.error("[Vault] ERROR - CredentialResolver: " + HASHICORP_VAULT_LOGIN_TYPE_PROPERTY +
						" not set! Please set it to one of the following values: AWS_ROLE, USER_PASS, TOKEN.");
				throw new RuntimeException("CredentialResolver:  Property " + HASHICORP_VAULT_LOGIN_TYPE_PROPERTY +
						" = " +	hashicorpVaultLoginType + ". This not a valid value. Please set it to one of the " +
						"following values: AWS_ROLE, USER_PASS, TOKEN.");
		}
	}

	/**
	 * Get Vault Object based on login type AWS_ROLE.
	 */
	private Vault getVaultOnAWSLogin(SslConfig sslConfig) throws VaultException, IOException {
		// Get ECS metadata file path
		String metadataFilePath = System.getenv("ECS_CONTAINER_METADATA_FILE");

		// Get Task ID from ECS metadata file
		File metadataFile = new File(metadataFilePath);
		String metadataJson = new String(Files.readAllBytes(metadataFile.toPath()));
		JsonParser jsonParser = new JsonParser();
		JsonObject metadata = jsonParser.parse(metadataJson).getAsJsonObject();
		String taskId = metadata.get("TaskARN").getAsString();

		// Get STS Assume Role credentials from ECS metadata file
		StsClient stsClient = StsClient.builder().region(hashicorpVaultAwsRegion).build();
		AssumeRoleRequest assumeRoleRequest = AssumeRoleRequest.builder()
				.roleArn(hashicorpVaultAwsRoleArn)
				.roleSessionName(taskId)
				.build();
		AssumeRoleResponse assumeRoleResponse = stsClient.assumeRole(assumeRoleRequest);
		String assumeRoleArn = assumeRoleResponse.assumedRoleUser().arn();

		final VaultConfig authConfig = new VaultConfig()
				.address(hashicorpVaultAddress)
				.openTimeout(60)       // Defaults to "VAULT_OPEN_TIMEOUT" environment variable
				.readTimeout(60)       // Defaults to "VAULT_READ_TIMEOUT" environment variable
				.sslConfig(sslConfig.build())   //"SSL Config" to use client certificate.
				.build();
		final Vault authVault = new Vault(authConfig);

		String awsAuthMount = "{\"Account\":\"" + hashicorpVaultAwsAccountId +
				"\",\"UserId\":\""+ taskId +
				"\",\"Arn\":\"" + assumeRoleArn + "\"}";

		fLogger.info("[Vault] INFO - CredentialResolver: awsAuthMount = " + awsAuthMount);

		String iamRequestUrl = Base64.getUrlEncoder().encodeToString("https://sts.amazonaws.com/".getBytes());
		String iamRequestBody = Base64.getUrlEncoder().encodeToString(
				"Action=GetCallerIdentity&Version=2011-06-15".getBytes());
		String iamRequestHeaders = "Content-Type: application/x-www-form-urlencoded\nHost: sts.amazonaws.com";

		AuthResponse authResp = authVault.auth().loginByAwsIam(
				hashicorpVaultAwsRoleName,
				iamRequestUrl,
				iamRequestBody,
				iamRequestHeaders,
				awsAuthMount
				);

		String vaultToken = authResp.getAuthClientToken();

		stsClient.close();

		final VaultConfig config = new VaultConfig()
				.address(hashicorpVaultAddress)
				.token(vaultToken)
				.openTimeout(60)       // Defaults to "VAULT_OPEN_TIMEOUT" environment variable
				.readTimeout(60)       // Defaults to "VAULT_READ_TIMEOUT" environment variable
				.sslConfig(sslConfig.build())
				.build();
		return new Vault(config);
	}

	/**
	 * Get Vault Object based on login type USER_PASS.
	 */
	private Vault getVaultOnUserPassLogin(SslConfig sslConfig) throws VaultException {
		final VaultConfig authConfig = new VaultConfig()
				.address(hashicorpVaultAddress)
				.openTimeout(60)       // Defaults to "VAULT_OPEN_TIMEOUT" environment variable
				.readTimeout(60)       // Defaults to "VAULT_READ_TIMEOUT" environment variable
				.sslConfig(sslConfig.build())   //"SSL Config" to use client certificate.
				.build();
		final Vault authVault = new Vault(authConfig);
		AuthResponse authResp = authVault.auth().
				loginByUserPass(hashicorpVaultUser, hashicorpVaultPassword);
		String vaultToken = authResp.getAuthClientToken();
		final VaultConfig config = new VaultConfig()
				.address(hashicorpVaultAddress)
				.token(vaultToken)
				.openTimeout(60)       // Defaults to "VAULT_OPEN_TIMEOUT" environment variable
				.readTimeout(60)       // Defaults to "VAULT_READ_TIMEOUT" environment variable
				.sslConfig(sslConfig.build())
				.build();
		return new Vault(config);
	}

	private Vault getVaultOnTokenLogin(SslConfig sslConfig) throws VaultException{
		final VaultConfig config = new VaultConfig()
				.address(hashicorpVaultAddress)
				.token(hashicorpVaultToken)
				.openTimeout(60)       // Defaults to "VAULT_OPEN_TIMEOUT" environment variable
				.readTimeout(60)       // Defaults to "VAULT_READ_TIMEOUT" environment variable
				.sslConfig(sslConfig.build())
				.build();
		return new Vault(config);
	}

	/**
	 * Resolve a credential.
	 */
	@Override
	public Map<String, String> resolve(Map<String, String> args) {
		
		String credId = args.get(ARG_ID);
		String credType = args.get(ARG_TYPE);
		Vault vault = null;
		
		String username = "";
		String password = "";
		String passphrase = "";
		String private_key = "";

		fLogger.info("[Vault] INFO - CredentialResolver: Credential ID = " + credId);
		fLogger.info("[Vault] INFO - CredentialResolver: Credential Type = " + credType);
		if(credId == null || credType == null) {
			fLogger.error("[Vault] ERROR - CredentialResolver: Credential ID or Credential Type is null.");
			throw new RuntimeException("CredentialResolver: Credential ID or Credential Type is null.");
		}
		// Connect to vault and retrieve credential
		SslConfig sslConfig = new SslConfig();
		sslConfig.verify(hashicorpVaultValidSSL.equalsIgnoreCase("true"));
		try {
			switch (hashicorpVaultLoginType){
				case "AWS_ROLE":
					try{
						vault = getVaultOnAWSLogin(sslConfig);
					}
					catch (IOException e){
						fLogger.error("[Vault] ERROR - CredentialResolver: " +
								"Unable to read ECS metadata file. Please check if ECS_CONTAINER_METADATA_FILE " +
								"environment variable is set correctly.", e);
						throw new RuntimeException("CredentialResolver: " +
								"Unable to read ECS metadata file. Please check if ECS_CONTAINER_METADATA_FILE " +
								"environment variable is set correctly.");
					}
					break;
				case "USER_PASS":
					vault = getVaultOnUserPassLogin(sslConfig);
					break;
				case "TOKEN":
					vault = getVaultOnTokenLogin(sslConfig);
					break;
			}
			LogicalResponse response;
			try {
				assert vault != null;
				response = vault.logical().read(credId);
			}
			catch (VaultException e){
				fLogger.error("[Vault] ERROR - CredentialResolver: " +
						"Unable to read credential from vault. Please check if the credential ID is correct.", e);
				throw new RuntimeException("CredentialResolver: " +
						"Unable to read credential from vault. Please check if the credential ID is correct.");
			}
			switch(credType) {
				// for below listed credential type , just retrieve username and password
				case CRED_TYPE_WINDOWS:
				case CRED_TYPE_SSH_PASSWORD:
				case CRED_TYPE_VMWARE:
				case CRED_TYPE_JDBC:
				case CRED_TYPE_JMS:
				case CRED_TYPE_BASIC_AUTH:
					username = response.getData().get("username");
					password = response.getData().get("password");
					if (isNullOrEmpty(password) || isNullOrEmpty(username)) {
						fLogger.error("[Vault] ERROR - CredentialResolver: " +
								"Invalid KV format in vault for credential type: "
								+ credType + ". Is not possible paring credential. " +
								"Please check the KV format in vault. Use the " +
								"following format: {\"username\":\"<username>\", \"password\"=\"<password>\"");
						throw new RuntimeException("CredentialResolver: " +
								"Invalid KV format in vault for credential type: " +
								 credType + ". Is not possible paring credential. ");
					}
					break;
					// for below listed credential type , retrieve username, password, ssh_passphrase, ssh_private_key
				case CRED_TYPE_SSH_PRIVATE_KEY:
				case "sn_cfg_ansible":
				case "sn_disco_certmgmt_certificate_ca":
				case "cfg_chef_credentials":
				case "infoblox":
				case "api_key":
					// Read operation
					username = response.getData().get("username");
					private_key = response.getData().get("password"); //use corresponding attribute name for private_key
					passphrase = response.getData().get("ssh_passphrase");
					break;
				case "aws": // access_key, secret_key 	// AWS Support
					username = response.getData().get("access_key");
					password = response.getData().get("secret_key");
					break;
				case "ibm": // softlayer_user, softlayer_key, bluemix_key
				case CRED_TYPE_AZURE: // tenant_id, client_id, auth_method, secret_key
				case CRED_TYPE_GCP: // email , secret_key
				default:
					fLogger.error("[Vault] ERROR - CredentialResolver: invalid credential type found.");
					throw new RuntimeException("CredentialResolver: invalid credential type found.");
			}
		} 
		catch (VaultException e) {
			// Catch block
			fLogger.error("### Unable to connect to Vault: " + hashicorpVaultAddress, e);
		}
		// the resolved credential is returned in a HashMap...
		Map<String, String> result = new HashMap<>();
		/*
		 *     String VAL_USER = "user";
		 *     String VAL_PSWD = "pswd";
		 *     String VAL_PASSPHRASE = "passphrase";
		 *     String VAL_PKEY = "pkey";
		 *     String VAL_AUTHPROTO = "authprotocol";
		 *     String VAL_AUTHKEY = "authkey";
		 *     String VAL_PRIVPROTO = "privprotocol";
		 *     String VAL_PRIVKEY = "privkey";
		 *     String VAL_SECRET_KEY = "secret_key";
		 *     String VAL_CLIENT_ID = "client_id";
		 *     String VAL_TENANT_ID = "tenant_id";
		 *     String VAL_EMAIL = "email";
		 */
		result.put(VAL_USER, username);
		if (isNullOrEmpty(private_key)) {
			result.put(VAL_PSWD, password);
		} else {
			result.put(VAL_PKEY, private_key);
		}
		result.put(VAL_PASSPHRASE, passphrase);
		return result;
	}

	private static boolean isNullOrEmpty(String str) {
		return str == null || str.isEmpty();
	}
	
	/**
	 * Return the API version supported by this class.
	 * Note: should be less than 1.1 for external credential resolver.
	 */
	@Override
	public String getVersion() {
		return "0.1";
	}

	//main method to test locally, provide your vault details and test it.
	// TODO: Remove this before moving to production
	public static void main(String[] args) {
		CredentialResolver obj = new CredentialResolver();
		// obj.loadProps();
		// use your local details for testing.
		obj.hashicorpVaultAddress = "<hashicorp url>";
		obj.hashicorpVaultToken = "<token>";

		Map<String, String> map = new HashMap<>();
		String credId = "kv/testwin";
		String credType = "windows";
		map.put(ARG_ID, credId);
		map.put(ARG_TYPE, credType);

		Map<String, String> result = obj.resolve(map );
		System.out.println("Result: " + result.toString());
	}
}