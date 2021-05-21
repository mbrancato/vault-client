import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VaultClientTest {
  HttpClient client = HttpClient.newHttpClient();
  String vaultAddr = System.getenv("VAULT_ADDR");
  String vaultToken = System.getenv("VAULT_TOKEN");

  @BeforeAll
  void setUpAll() {
    if (vaultAddr == null || vaultToken == null) {
      throw new RuntimeException("The VAULT_ADDR and VAULT_TOKEN must be set for tests.");
    }
  }

  @Test
  void readKvV2() throws IOException, InterruptedException {
    Random rand = new Random();

    // Write a random value to kv-v2
    String secretName = "kv_v2_read";
    String testValue = String.valueOf(rand.nextInt(50));
    String data = String.format("{\"data\": {\"foo\": \"%s\"}}", testValue);
    String url = String.format("%s/v1/secret/data/%s", vaultAddr, secretName);
    HttpRequest.Builder requestBuilder =
        HttpRequest.newBuilder().timeout(Duration.ofSeconds(3)).uri(URI.create(url));
    requestBuilder = requestBuilder.method("POST", HttpRequest.BodyPublishers.ofString(data));
    requestBuilder.header("X-Vault-Token", vaultToken);
    HttpRequest request = requestBuilder.build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

    VaultClient vc = new VaultClient();
    String result = vc.readKv(secretName, "foo");

    Assertions.assertEquals(200, response.statusCode());
    Assertions.assertEquals(testValue, result);
  }

  @Test
  void readKvV2Ttl() throws IOException, InterruptedException {
    Random rand = new Random();

    // Write a random value to kv-v2 with 5 second TTL
    String secretName = "kv_v2_read_ttl";
    String testValue = String.valueOf(rand.nextInt(50));
    String data = String.format("{\"data\": {\"foo\": \"%s\", \"ttl\": \"5\"}}", testValue);
    String url = String.format("%s/v1/secret/data/%s", vaultAddr, secretName);
    HttpRequest.Builder requestBuilder =
        HttpRequest.newBuilder().timeout(Duration.ofSeconds(3)).uri(URI.create(url));
    requestBuilder = requestBuilder.method("POST", HttpRequest.BodyPublishers.ofString(data));
    requestBuilder.header("X-Vault-Token", vaultToken);
    HttpRequest request = requestBuilder.build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

    VaultClient vc = new VaultClient();
    String result = vc.readKv(secretName, "foo");

    Assertions.assertEquals(200, response.statusCode());
    Assertions.assertEquals(testValue, result);

    // Write a new random value to kv-v2 with 5 second TTL
    String newTestValue = String.valueOf(rand.nextInt(50));
    data = String.format("{\"data\": {\"foo\": \"%s\", \"ttl\": \"5\"}}", newTestValue);
    requestBuilder = HttpRequest.newBuilder().timeout(Duration.ofSeconds(3)).uri(URI.create(url));
    requestBuilder = requestBuilder.method("POST", HttpRequest.BodyPublishers.ofString(data));
    requestBuilder.header("X-Vault-Token", vaultToken);
    request = requestBuilder.build();
    response = client.send(request, HttpResponse.BodyHandlers.ofString());

    // Initially, the result should be the old value read from cache
    result = vc.readKv(secretName, "foo");

    Assertions.assertEquals(200, response.statusCode());
    Assertions.assertEquals(testValue, result);

    TimeUnit.SECONDS.sleep(5);

    // After 5 seconds, the result should be the new value as the TTL expired
    result = vc.readKv(secretName, "foo");

    Assertions.assertEquals(200, response.statusCode());
    Assertions.assertEquals(newTestValue, result);
  }
}
