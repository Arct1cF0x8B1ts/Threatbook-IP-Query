package com.example.ipquerytools;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class Main extends Application {
    @Override
    public void start(Stage primaryStage) {
        try {
            FXMLLoader fxmlLoader = new FXMLLoader(Main.class.getResource("form.fxml"));
            Parent root = fxmlLoader.load();

            // 获取控制器
            Controller controller = fxmlLoader.getController();

            Scene scene = new Scene(root);
            primaryStage.setTitle("在线微步情报威胁IP查询工具 by hu5k7");
            primaryStage.setResizable(false);
            primaryStage.setScene(scene);
            primaryStage.show();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        launch();
    }
}