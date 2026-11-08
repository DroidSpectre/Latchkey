package io.latchkey.bridge;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class Json {
    private Json() {
    }

    static JSONObject obj() {
        return new JSONObject();
    }

    static JSONObject put(JSONObject object, String key, Object value) {
        try {
            object.put(key, value);
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
        return object;
    }

    static JSONArray arr() {
        return new JSONArray();
    }

    static JSONArray add(JSONArray array, Object value) {
        array.put(value);
        return array;
    }
}
