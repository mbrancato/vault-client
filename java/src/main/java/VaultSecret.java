import com.google.gson.JsonObject;

import java.util.Date;

public class VaultSecret {
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
