import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class VaultSecretUpdateRunnable extends VaultClientMethods implements Runnable {
  private VaultSecret secret;
  private String vaultToken;
  private String vaultAddr;

  public void setSecret(VaultSecret secret) {
    this.secret = secret;
  }

  public void setVaultToken(String vaultToken) {
    this.vaultToken = vaultToken;
  }

  public void setVaultAddr(String vaultAddr) {
    this.vaultAddr = vaultAddr;
  }

  public void run() {

    Map<String, String> vaultHeaders = new HashMap<>();
    String renewalResultJson = null;
    String renewalDataJson;
    VaultRenewalData renewalData = new VaultRenewalData();
    Gson gson = new Gson();

    vaultHeaders.put("X-Vault-Token", this.vaultToken);

    renewalData.lease_id = this.secret.leaseId;
    renewalData.increment = this.secret.leaseDuration;
    renewalDataJson = gson.toJson(renewalData);

    try {
      renewalResultJson =
          this.httpPost(this.vaultAddr + "/v1/sys/leases/renew", vaultHeaders, renewalDataJson);
    } catch (IOException | InterruptedException e) {
      e.printStackTrace();
    }

    JsonObject renewalResult = gson.fromJson(renewalResultJson, JsonObject.class);
    if (renewalResult != null && this.getDottedJsonPath("lease_id", renewalResult) != null) {
      secret.leaseTime = new Date();
      secret.leaseId = this.getDottedJsonPath("lease_id", renewalResult).getAsString();
      secret.renewable = this.getDottedJsonPath("renewable", renewalResult).getAsBoolean();
      secret.leaseDuration = this.getDottedJsonPath("lease_duration", renewalResult).getAsLong();
    }
    secret.updateLock = false;
  }
}
