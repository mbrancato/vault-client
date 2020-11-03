import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VaultClient extends VaultClientMethods {
  private final Logger logger = Logger.getLogger(VaultClient.class.getName());
  private String vaultAddr;
  private String vaultToken;
  private String vaultNamespace;
  private String vaultAccessor = null;
  private String authMethod = null;
  private String authPath = null;
  private String authRole = null;
  private List<String> vaultPolicies = null;
  private Date vaultTokenLeaseTime;
  private long vaultTokenLeaseDuration = 0;
  private boolean authenticated = false;
  private final Map<String, VaultSecret> secrets = new HashMap<String, VaultSecret>();

  VaultClient() {
    this.vaultToken = System.getenv("VAULT_TOKEN");
    this.vaultAddr = System.getenv("VAULT_ADDR");
    this.vaultNamespace = System.getenv("VAULT_NAMESPACE");

    if (this.vaultToken != null && this.vaultAddr != null) {
      this.logger.log(Level.FINE, "Using existing Token for authentication.");
      this.authenticated = true;
    }
  }

  public String getVaultAddr() {
    return vaultAddr;
  }

  public void setVaultAddr(String vaultAddr) {
    this.vaultAddr = vaultAddr;
  }

  public String getVaultAccessor() {
    return vaultAccessor;
  }

  public List<String> getVaultPolicies() {
    return vaultPolicies;
  }

  public String getVaultNamespace() {
    return vaultNamespace;
  }

  public void setVaultNamespace(String vaultNamespace) {
    this.vaultNamespace = vaultNamespace;
  }

  public boolean isAuthenticated() {
    return authenticated;
  }

  public String getAuthMethod() {
    return authMethod;
  }

  public void setAuthMethod(String authMethod) {
    this.authMethod = authMethod;
  }

  public String getAuthPath() {
    return authPath;
  }

  public void setAuthPath(String authPath) {
    this.authPath = authPath;
  }

  public String getAuthRole() {
    return authRole;
  }

  public void setAuthRole(String authRole) {
    this.authRole = authRole;
  }

  public void setVaultToken(String vaultToken) {
    this.vaultToken = vaultToken;
  }

  public boolean login() throws IOException, InterruptedException, AuthenticationException {
    logger.log(Level.FINE, "Performing Auth");
    boolean result = false;

    if (this.authPath == null) {
      logger.log(Level.FINE, "Auth path null");
      this.authPath = this.authMethod;
    }

    switch (this.authMethod) {
      case "gcp":
        result = this.loginGcp();
        break;
      case "jwt":
        result = this.loginJwt(null);
        break;
      default:
        break;
    }
    if (!result) {
      throw new AuthenticationException("Unable to authenticate to Vault.");
    } else {
      return true;
    }
  }

  public String readKv(String name, String key)
      throws InterruptedException, IOException, AuthenticationException {
    // Assume kv-v2 mounted at /secret
    return readKv(name, key, 0, "/secret", 2);
  }

  public String readKv(String name, String key, int version, String mountPath, int kvVersion)
      throws InterruptedException, IOException, AuthenticationException {
    String path;
    String kvKey;
    if (kvVersion == 1) {
      path = String.format("%s/%s", mountPath, name);
      kvKey = String.format("data.%s", key);
      return read(path, kvKey);
    } else if (kvVersion == 2) {
      path = String.format("%s/data/%s?version=%d", mountPath, name, version);
      kvKey = String.format("data.data.%s", key);
      return read(path, kvKey);
    } else {
      logger.severe("Unknown Key-Value secret engine version");
    }
    return null;
  }

  public String read(String path, String key)
      throws IOException, InterruptedException, AuthenticationException {
    JsonElement value = readJsonElement(path, key);
    if (value != null) {
      try {
        return value.getAsString();
      } catch (UnsupportedOperationException e) {
        Gson gson = new Gson();
        return gson.toJson(value);
      }
    }
    return null;
  }

  private JsonElement readJsonElement(String path, String key)
      throws IOException, InterruptedException, AuthenticationException {
    logger.log(Level.FINE, String.format("%s read", new Date()));
    final Date currentTime = new Date();
    long secondsSinceTokenLease;
    long secondsSinceSecretLease;

    if (path == null || key == null) {
      return null;
    }

    if (path.charAt(0) != '/') {
      path = "/" + path;
    }

    if (!this.authenticated) {
      this.authenticated = this.login();
    }

    secondsSinceTokenLease = (currentTime.getTime() - this.vaultTokenLeaseTime.getTime()) / 1000;
    if ((float) secondsSinceTokenLease > ((float) this.vaultTokenLeaseDuration * (2.0 / 3.0))) {
      // TODO: Renew vault token
    }

    if (!this.secrets.containsKey(path)) {
      logger.log(Level.FINE, "Secret is new");
      this.secrets.put(path, new VaultSecret(path));
    }

    VaultSecret secret = this.secrets.get(path);
    if (!secret.leased) {
      // No lease yet
      getSecret(path);
    } else {
      secondsSinceSecretLease = (currentTime.getTime() - secret.leaseTime.getTime()) / 1000;
      if (secondsSinceSecretLease >= secret.leaseDuration) {
        // Lease expired
        getSecret(path);
      } else if ((float) secondsSinceSecretLease > ((float) secret.leaseDuration * (2.0 / 3.0))) {
        if (secret.renewable) {
          // Lease is renewable
          if (!secret.updateLock) {
            secret.updateLock = true;
            updateSecret(secret);
          }
        } else {
          // Lease is not renewable
          getSecret(path);
        }
      }
    }

    logger.log(Level.INFO, String.format("Lease time: %s", secret.leaseTime));
    if (secret.leased) {
      return getDottedJsonPath(key, secret.value);
    } else {
      return null;
    }
  }

  private void getSecret(String path) throws IOException, InterruptedException {
    String secretJson;
    VaultSecret secret = this.secrets.get(path);
    Map<String, String> vaultHeaders = new HashMap<>();
    Gson gson = new Gson();

    vaultHeaders.put("X-Vault-Token", this.vaultToken);

    secretJson = this.httpGet(this.vaultAddr + "/v1" + path, vaultHeaders);
    if (secretJson != null) {
      secret.leaseTime = new Date();
      secret.value = gson.fromJson(secretJson, JsonObject.class);
      secret.leased = true;
      if (this.getDottedJsonPath("renewable", secret.value) != null) {
        secret.renewable = this.getDottedJsonPath("renewable", secret.value).getAsBoolean();
      }
      if (this.getDottedJsonPath("lease_duration", secret.value) != null) {
        secret.leaseDuration = this.getDottedJsonPath("lease_duration", secret.value).getAsInt();
      } else {
        secret.leaseDuration = 0;
      }
      // Implement TTL support for KV V2
      if (this.getDottedJsonPath("data.data.ttl", secret.value) != null) {
        secret.leaseDuration = this.getDottedJsonPath("data.data.ttl", secret.value).getAsInt();
      }
      if (this.getDottedJsonPath("lease_id", secret.value) != null) {
        secret.leaseId = this.getDottedJsonPath("lease_id", secret.value).getAsString();
      }
    }
  }

  private void updateSecret(VaultSecret secret) {
    VaultSecretUpdateRunnable updater = new VaultSecretUpdateRunnable();
    updater.setSecret(secret);
    updater.setVaultAddr(this.vaultAddr);
    updater.setVaultToken(this.vaultToken);

    new Thread(updater).start();
  }

  private boolean loginGcp() throws IOException, InterruptedException {
    logger.log(Level.FINE, "Performing GCP Login");
    Map<String, String> googleHeaders = new HashMap<>();
    String googleUrlParams;
    String googleMetadatUrl;
    String jwt;

    googleHeaders.put("Metadata-Flavor", "Google");

    if (this.authRole != null) {
      googleUrlParams =
          String.format(
              "audience=vault/%s&format=full",
              URLEncoder.encode(this.authRole, StandardCharsets.UTF_8.toString()));
    } else {
      googleUrlParams = "audience=vault&format=full";
    }

    googleMetadatUrl =
        String.format(
            "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?%s",
            googleUrlParams);
    jwt = this.httpGet(googleMetadatUrl, googleHeaders);

    return this.loginJwt(jwt);
  }

  private boolean loginJwt(String jwt) throws IOException, InterruptedException {
    logger.log(Level.FINE, "Performing JWT Login");
    String loginDataJson;
    String loginResultJson;
    Type listOfStrings = new TypeToken<ArrayList<String>>() {}.getType();
    final String loginPath = String.format("/v1/auth/%s/login", this.authPath);
    VaultLoginData loginData = new VaultLoginData();

    Gson gson = new Gson();

    loginData.role = this.authRole;
    loginData.jwt = jwt;
    loginDataJson = gson.toJson(loginData);
    loginResultJson = this.httpPost(this.vaultAddr + loginPath, loginDataJson);
    if (loginResultJson == null) {
      logger.severe("An error occurred attempting to login to Vault");
      return false;
    }
    JsonObject loginResponse = gson.fromJson(loginResultJson, JsonObject.class);

    if (this.getDottedJsonPath("auth.client_token", loginResponse) != null) {
      this.vaultTokenLeaseTime = new Date();
      this.vaultToken = this.getDottedJsonPath("auth.client_token", loginResponse).getAsString();
      if (this.getDottedJsonPath("auth.accessor", loginResponse) != null) {
        this.vaultAccessor = this.getDottedJsonPath("auth.accessor", loginResponse).getAsString();
      }
      if (this.getDottedJsonPath("auth.lease_duration", loginResponse) != null) {
        this.vaultTokenLeaseDuration =
            this.getDottedJsonPath("auth.lease_duration", loginResponse).getAsLong();
      }
      if (this.getDottedJsonPath("auth.policies", loginResponse) != null) {
        this.vaultPolicies =
            gson.fromJson(this.getDottedJsonPath("auth.policies", loginResponse), listOfStrings);
      }
      this.authenticated = true;
      return true;
    }
    return false;
  }
}
