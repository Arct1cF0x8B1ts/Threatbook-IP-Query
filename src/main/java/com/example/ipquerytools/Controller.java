package com.example.ipquerytools;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.HttpEntity;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class Controller {
    @FXML
    private TextField InputAPIBOX;
    @FXML
    private Button ExecuteButton;
    @FXML
    private TextArea OutPutBox;
    @FXML
    private TextArea IPTextBox;


    @FXML
    private void onExecuteButtonClick(ActionEvent event){
        OutPutBox.clear();
        if (InputAPIBOX.getText().isEmpty()){
            Alert alert = new Alert(AlertType.WARNING);
            alert.setTitle("警告");
            alert.setHeaderText(null);
            alert.setContentText("API不能为空！");
            alert.showAndWait();
        }else{
            String[] lines = IPTextBox.getText().split("\n");
            StringBuilder resultBuilder = new StringBuilder();

            for (String line : lines) {
                String trimmedLine = line.trim();
                if (!trimmedLine.isEmpty()) {
                    if (!isValidIP(trimmedLine))
                    {
                        Alert alert = new Alert(AlertType.WARNING);
                        alert.setTitle("警告");
                        alert.setHeaderText(null);
                        alert.setContentText(trimmedLine+" > IP格式校验失败！");
                        alert.showAndWait();
                        break;

                    }else{
                        resultBuilder.append(trimmedLine).append(",");
                    }
                }
            }
            String result = resultBuilder.toString();
            if (!result.isEmpty()) {
                result = result.substring(0, result.length() - 1);
            }
            QueryIP(result);

        }

    }
    private boolean isValidIP(String ip) {
        String ipAddressPattern = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";

        Pattern pattern = Pattern.compile(ipAddressPattern);
        Matcher matcher = pattern.matcher(ip);

        return matcher.matches();
    }

    private void QueryIP(String IPS){
        String result;
        String THREATBOOK_API_URL = "https://api.threatbook.cn/v3/scene/ip_reputation";


        try{
            HttpPost httpPost = new HttpPost(THREATBOOK_API_URL);

            List<NameValuePair> resp = new ArrayList<>();
            resp.add(new BasicNameValuePair("resource", IPS));
            resp.add(new BasicNameValuePair("apikey", InputAPIBOX.getText()));
            resp.add(new BasicNameValuePair("lang","zh"));

            httpPost.setEntity(new UrlEncodedFormEntity(resp));
            try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
                try (CloseableHttpResponse response = httpclient.execute(httpPost)) {
                    HttpEntity entity = response.getEntity();
                    result = EntityUtils.toString(entity);

                    JSONObject jsonResponse = new JSONObject(result);
                    JSONObject data = jsonResponse.getJSONObject("data");
                    for (String ip : data.keySet()) {
                        JSONObject ipData = data.getJSONObject(ip);
                        boolean is_malicious = ipData.getBoolean("is_malicious");
                        JSONObject basic = ipData.getJSONObject("basic");
                        JSONObject location = basic.getJSONObject("location");
                        String city = location.getString("city");

                        //is_malicious
                        if(is_malicious){
                            OutPutBox.appendText(ip + " 恶意IP " +city + "\n");
                        }
                    }
                }
            } catch (IOException | ParseException e) {
                e.printStackTrace();
            }

        } catch (Exception e){
            e.printStackTrace();
        }
    }
}