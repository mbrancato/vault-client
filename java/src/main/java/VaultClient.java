import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VaultClient {
  private final Logger logger = Logger.getLogger(VaultClient.class.getName());
  private final Map<String, VaultSecret> secrets = new HashMap<>();
  private String vaultAddr;
  private String vaultToken;
  private String vaultNamespace;
  private String vaultAccessor = null;
  private String authMethod;
  private String authPath;
  private String authRole;
  private List<String> vaultPolicies = null;
  private Date vaultTokenLeaseTime;
  private long vaultTokenLeaseDuration = 0;
  private boolean authenticated = false;

  VaultClient() {
    this(System.getenv("VAULT_ADDR"));
  }

  VaultClient(String vaultAddr) {
    this(vaultAddr, "", "");
  }

  // This is probably the most common case needed
  VaultClient(String vaultAddr, String authMethod, String authRole) {
    this(vaultAddr, authMethod, authRole, "");
  }

  VaultClient(String vaultAddr, String authMethod, String authRole, String authPath) {
    this.vaultToken = System.getenv("VAULT_TOKEN");
    this.vaultNamespace = System.getenv("VAULT_NAMESPACE");
    this.vaultAddr = vaultAddr;
    this.authMethod = authMethod;
    this.authRole = authRole;
    this.authPath = authPath;

    if (this.vaultToken != null && this.vaultAddr != null) {
      this.logger.log(Level.FINE, "Using existing Token for authentication.");
      this.authenticated = true;
    }
  }

  public String getVaultAddr() {
    return vaultAddr;
  }

  public String getVaultAccessor() {
    return vaultAccessor;
  }

  public String getVaultNamespace() {
    return vaultNamespace;
  }

  public String getAuthMethod() {
    return authMethod;
  }

  public String getAuthPath() {
    return authPath;
  }

  public String getAuthRole() {
    return authRole;
  }

  public List<String> getVaultPolicies() {
    return vaultPolicies;
  }

  public boolean isAuthenticated() {
    return authenticated;
  }

  public void setVaultAddr(String vaultAddr) {
    this.vaultAddr = vaultAddr;
  }

  public void setVaultAccessor(String vaultAccessor) {
    this.vaultAccessor = vaultAccessor;
  }

  public void setVaultNamespace(String vaultNamespace) {
    this.vaultNamespace = vaultNamespace;
  }

  public void setAuthMethod(String authMethod) {
    this.authMethod = authMethod;
  }

  public void setAuthPath(String authPath) {
    this.authPath = authPath;
  }

  public void setAuthRole(String authRole) {
    this.authRole = authRole;
  }

  public void setVaultToken(String vaultToken) {
    this.vaultToken = vaultToken;
  }

  public String readKv(String name, String key) throws IOException {
    // Assume kv-v2 mounted at /secret
    return readKv(name, key, 0, "/secret", 2);
  }

  public String readKv(String name, String key, int version, String mountPath, int kvVersion)
      throws IOException {
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

  public String read(String path, String key) throws IOException {
    JsonElement value = readJsonElement(path, key);
    if (value != null) {
      try {
        return value.getAsString();
      } catch (UnsupportedOperationException e) {
        final Gson gson = new Gson();
        return gson.toJson(value);
      }
    }
    return null;
  }

  public boolean login() throws IOException, AuthenticationException {
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
        // JWT login method should really be called directly
        // TODO: Find a clean way to reauthenticate when token using JWT auth expires
      default:
        break;
    }
    if (!result) {
      throw new AuthenticationException("Unable to authenticate to Vault.");
    } else {
      return true;
    }
  }

  private boolean loginGcp() throws IOException {
    logger.log(Level.FINE, "Performing GCP Login");
    final Map<String, String> googleHeaders = new HashMap<>();
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

  private boolean loginJwt(String jwt) {
    logger.log(Level.FINE, "Performing JWT Login");
    String loginDataJson;
    String loginResultJson;
    final Type listOfStrings = new TypeToken<ArrayList<String>>() {}.getType();
    final String loginPath = String.format("/v1/auth/%s/login", this.authPath);
    final VaultLoginJwtData loginData = new VaultLoginJwtData();
    final Gson gson = new Gson();

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

  private String httpGet(String uri, Map<String, String> headers) {
    return httpRequest("GET", uri, headers, null);
  }

  // With the Vault API, currently POST and PUT are interchangeable methods
  private String httpPost(String uri, String data) {
    return httpRequest("POST", uri, new HashMap<>(), data);
  }

  private String httpPost(String uri, Map<String, String> headers, String data) {
    return httpRequest("POST", uri, headers, data);
  }

  private String httpRequest(String method, String uri, Map<String, String> headers, String data) {
    HttpClient client = HttpClient.newHttpClient();
    // TODO: Allow timeout to be configurable
    HttpRequest.Builder requestBuilder =
        HttpRequest.newBuilder().timeout(Duration.ofSeconds(3)).uri(URI.create(uri));

    if (data == null) {
      requestBuilder = requestBuilder.method(method, HttpRequest.BodyPublishers.noBody());
    } else {
      requestBuilder = requestBuilder.method(method, HttpRequest.BodyPublishers.ofString(data));
    }

    for (Map.Entry<String, String> entry : headers.entrySet())
      requestBuilder.header(entry.getKey(), entry.getValue());

    HttpRequest request = requestBuilder.build();
    try {
      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() > 200 && response.statusCode() < 400) {
        logger.warning(
            "Unexpected response. The Vault client is not configured to handle redirects: "
                + response.headers()
                + " : "
                + response.body());
        return null;
      } else if (response.statusCode() >= 400) {
        logger.severe("Error occurred: " + response.body());
        return null;
      }

      return response.body();
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
    }
    return null;
  }

  private void getSecret(VaultSecret secret) {
    String secretJson;
    final Map<String, String> vaultHeaders = new HashMap<>();
    final Gson gson = new Gson();

    vaultHeaders.put("X-Vault-Token", this.vaultToken);

    secretJson = this.httpGet(this.vaultAddr + "/v1" + secret.path, vaultHeaders);
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

  private void renewSecret(VaultSecret secret) {
    final VaultSecretRenewRunnable renewer = new VaultSecretRenewRunnable();
    renewer.setSecret(secret);

    new Thread(renewer).start();
  }

  private void updateSecret(VaultSecret secret) {
    final VaultSecretUpdateRunnable updater = new VaultSecretUpdateRunnable();
    updater.setSecret(secret);

    new Thread(updater).start();
  }

  private JsonElement readJsonElement(String path, String key) throws IOException {
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
      try {
        this.authenticated = this.login();
      } catch (AuthenticationException e) {
        e.printStackTrace();
      }
    }

    if (this.vaultTokenLeaseTime != null) {
      secondsSinceTokenLease = (currentTime.getTime() - this.vaultTokenLeaseTime.getTime()) / 1000;
      if ((float) secondsSinceTokenLease > ((float) this.vaultTokenLeaseDuration * (2.0 / 3.0))) {
        try {
          this.authenticated = this.login();
        } catch (AuthenticationException e) {
          e.printStackTrace();
        }
      }
    }

    if (!this.secrets.containsKey(path)) {
      logger.log(Level.FINE, "Secret is new");
      this.secrets.put(path, new VaultSecret(path));
    }

    VaultSecret secret = this.secrets.get(path);
    if (!secret.leased) {
      // No lease yet
      getSecret(secret);
    } else {
      secondsSinceSecretLease = (currentTime.getTime() - secret.leaseTime.getTime()) / 1000;
      if (secondsSinceSecretLease >= secret.leaseDuration) {
        // Lease expired
        getSecret(secret);
      } else if ((float) secondsSinceSecretLease > ((float) secret.leaseDuration * (2.0 / 3.0))) {
        if (secret.renewable) {
          // Lease is renewable
          if (!secret.updateLock) {
            secret.updateLock = true;
            renewSecret(secret);
          }
        } else {
          // Lease is not renewable
          if (!secret.updateLock) {
            secret.updateLock = true;
            updateSecret(secret);
          }
        }
      }
    }

    logger.log(
        Level.INFO, String.format("Lease time for secret: %s : %s", secret.path, secret.leaseTime));
    if (secret.leased) {
      return getDottedJsonPath(key, secret.value);
    } else {
      return null;
    }
  }

  private JsonElement getDottedJsonPath(String path, JsonObject object) {
    List<String> pathList = Arrays.asList(path.split("\\.").clone());
    return getListJsonPath(pathList, object);
  }

  private JsonElement getListJsonPath(List<String> path, JsonObject object) {
    JsonElement result = object.get(path.get(0));
    if (result == null) {
      return null;
    }
    if (path.size() > 1) {
      return getListJsonPath(path.subList(1, path.size()), result.getAsJsonObject());
    } else {
      return result;
    }
  }

  public static class VaultSecret {
    public String path;
    public JsonObject value;
    public String leaseId;
    public Date leaseTime;
    public long leaseDuration;
    public boolean leased = false;
    public boolean renewable = false;
    public boolean updateLock = false;

    public VaultSecret(String path) {
      this.path = path;
    }
  }

  private static class VaultLoginJwtData {
    public String role;
    public String jwt;
  }

  private static class VaultRenewalData {
    public String lease_id;
    public long increment;
  }

  private class VaultSecretUpdateRunnable implements Runnable {
    private VaultSecret secret;

    public void setSecret(VaultSecret secret) {
      this.secret = secret;
    }

    public void run() {

      VaultClient.this.getSecret(this.secret);

      this.secret.updateLock = false;
    }
  }

  private class VaultSecretRenewRunnable implements Runnable {
    private VaultSecret secret;

    public void setSecret(VaultSecret secret) {
      this.secret = secret;
    }

    public void run() {

      String renewalResultJson;
      String renewalDataJson;
      final VaultRenewalData renewalData = new VaultRenewalData();
      final Map<String, String> vaultHeaders = new HashMap<>();
      final Gson gson = new Gson();

      vaultHeaders.put("X-Vault-Token", VaultClient.this.vaultToken);

      renewalData.lease_id = this.secret.leaseId;
      renewalData.increment = this.secret.leaseDuration;
      renewalDataJson = gson.toJson(renewalData);

      renewalResultJson =
          VaultClient.this.httpPost(
              VaultClient.this.vaultAddr + "/v1/sys/leases/renew", vaultHeaders, renewalDataJson);

      JsonObject renewalResult = gson.fromJson(renewalResultJson, JsonObject.class);
      if (renewalResult != null
          && VaultClient.this.getDottedJsonPath("lease_id", renewalResult) != null) {
        secret.leaseTime = new Date();
        secret.leaseId =
            VaultClient.this.getDottedJsonPath("lease_id", renewalResult).getAsString();
        secret.renewable =
            VaultClient.this.getDottedJsonPath("renewable", renewalResult).getAsBoolean();
        secret.leaseDuration =
            VaultClient.this.getDottedJsonPath("lease_duration", renewalResult).getAsLong();
      }
      secret.updateLock = false;
    }
  }
}
