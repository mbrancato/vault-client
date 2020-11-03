import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class VaultClientMethods {
  private final Logger logger = Logger.getLogger(VaultClient.class.getName());

  public JsonElement getDottedJsonPath(String path, JsonObject object) {
    List<String> pathList = Arrays.asList(path.split("\\.").clone());
    return getListJsonPath(pathList, object);
  }

  public JsonElement getListJsonPath(List<String> path, JsonObject object) {
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

  public String httpGet(String uri, Map<String, String> headers)
      throws IOException, InterruptedException {
    return httpRequest("GET", uri, headers, null);
  }

  // With the Vault API, currently POST and PUT are interchangeable methods
  public String httpPost(String uri, String data) throws IOException, InterruptedException {
    return httpRequest("POST", uri, new HashMap<>(), data);
  }

  public String httpPost(String uri, Map<String, String> headers, String data)
      throws IOException, InterruptedException {
    return httpRequest("POST", uri, headers, data);
  }

  private String httpRequest(String method, String uri, Map<String, String> headers, String data)
      throws IOException, InterruptedException {
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
  }
}
