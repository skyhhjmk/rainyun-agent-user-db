package com.rainyun.agent.rainyun;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rainyun.agent.service.SettingsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class RainyunClient {
    @Inject ObjectMapper mapper;
    @Inject SettingsService settings;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();

    public Profile verify(String apiKey) {
        JsonNode data = get(apiKey, "/user/").path("data");
        long uid = number(data.path("ID"));
        long inviter = number(data.path("Inviter"));
        long configuredAgentUid = settings.rainyunAgentUid();
        if (uid <= 0) throw new RainyunException("雨云账号信息中缺少有效 UID");
        if (configuredAgentUid <= 0) throw new RainyunException("平台尚未配置代理商 UID");
        if (inviter != configuredAgentUid) throw new RainyunException("此雨云账号的上级 UID 与本代理商不匹配");
        boolean realNameVerified = isRealNameVerified(data);
        boolean wechatBound = !text(data.path("WechatOpenID")).isBlank();
        return new Profile(uid, text(data.path("Name")), text(data.path("Email")), inviter, realNameVerified, wechatBound);
    }

    public List<ResourceView> resources(String apiKey) {
        String options = "{\"columnFilters\":{},\"sort\":[],\"page\":1,\"perPage\":100}";
        String encoded = URLEncoder.encode(options, StandardCharsets.UTF_8);
        List<ResourceView> result = new ArrayList<>();
        collect(result, apiKey, "RCS", "/product/rcs?options=" + encoded);
        collect(result, apiKey, "RGS", "/product/rgs/?options=" + encoded);
        collect(result, apiKey, "ROS", "/product/ros/instance/?options=" + encoded);
        return result;
    }

    private void collect(List<ResourceView> out, String apiKey, String type, String path) {
        try {
            JsonNode root = get(apiKey, path);
            JsonNode records = root.path("data").path("Records");
            if (!records.isArray()) records = root.path("data").path("records");
            if (!records.isArray()) return;
            for (JsonNode item : records) {
                String id = first(item, "ID", "id");
                String name = first(item, "Tag", "tag", "Name", "name", "HostName");
                String status = first(item, "Status", "status");
                String region = item.path("Node").path("ChineseName").asText("");
                if (region.isBlank()) region = item.path("Node").path("Region").asText("");
                String address = first(item, "MainIPv4", "NatPublicIP");
                out.add(new ResourceView(type, id, name.isBlank() ? type + "-" + id : name, status, region, address));
            }
        } catch (RuntimeException ignored) {
            out.add(new ResourceView(type, "", "暂时无法读取此类资源", "API 错误", "", ""));
        }
    }

    private JsonNode get(String apiKey, String path) {
        try {
            String baseUrl = settings.rainyunApiBaseUrl();
            String root = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
            HttpRequest request = HttpRequest.newBuilder(URI.create(root + path))
                    .timeout(Duration.ofSeconds(settings.rainyunTimeoutSeconds()))
                    .header("x-api-key", apiKey)
                    .header("Accept", "application/json")
                    .header("User-Agent", "rainyun-agent-user-db/1.0")
                    .GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) throw new RainyunException("Rainyun API rejected request");
            JsonNode rootNode = mapper.readTree(response.body());
            int code = rootNode.path("code").asInt(200);
            if (code != 0 && code != 200) throw new RainyunException("Rainyun API returned error code " + code);
            return rootNode;
        } catch (RainyunException e) { throw e; }
        catch (Exception e) { throw new RainyunException("无法连接雨云 API，请稍后重试"); }
    }

    private long number(JsonNode node) {
        if (node.isNumber()) return node.asLong();
        try { return Long.parseLong(node.asText()); } catch (Exception ignored) { return 0; }
    }
    private String text(JsonNode node) { return node.isMissingNode() || node.isNull() ? "" : node.asText(""); }
    private boolean isRealNameVerified(JsonNode data) {
        JsonNode certify = data.path("Certify");
        if (certify.isBoolean()) return certify.asBoolean();
        if (certify.isNumber()) {
            int value = certify.asInt();
            if (value == 1) return true;
            if (value == 0) return false;
        } else if (certify.isTextual()) {
            String value = normalize(certify.asText());
            if (value.equals("1") || isApproved(value)) return true;
            if (value.equals("0")) return false;
        }
        // The live Rainyun profile returned Certify=1 and CertifyStatus=passed.
        // If the numeric field is absent or has an unknown value, accept only a known pass label.
        return isApproved(normalize(text(data.path("CertifyStatus"))));
    }
    private boolean isApproved(String value) {
        return value.equals("passed") || value.equals("approved") || value.equals("verified")
                || value.equals("certified") || value.equals("success")
                || value.equals("已认证") || value.equals("已实名") || value.equals("认证通过")
                || value.equals("实名认证通过");
    }
    private String normalize(String value) { return value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT); }
    private String first(JsonNode node, String... fields) {
        for (String field : fields) { String value = node.path(field).asText(""); if (!value.isBlank()) return value; }
        return "";
    }

    public record Profile(long uid, String name, String email, long inviterUid,
                          boolean realNameVerified, boolean wechatBound) {}
    public record ResourceView(String type, String resourceId, String name, String status, String region, String address) {}
    public static class RainyunException extends RuntimeException { public RainyunException(String message) { super(message); } }
}
