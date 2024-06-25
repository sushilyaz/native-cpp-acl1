package org.example;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class Main extends Application {

    private final FileAccessControl fileAccessControl = new FileAccessControl();

    @Override
    public void start(Stage primaryStage) {
        Button blockAccessButton = new Button("Block All");
        Button allowAccessButton = new Button("Allow Access");
        Button unblockSpecificButton = new Button("Unblock Specific");
        TextField pathField = new TextField();
        pathField.setPromptText("Enter path to unblock");

        blockAccessButton.setOnAction(event -> {
            boolean result = fileAccessControl.blockAccess();
            showAlert(result ? "Access to the folder has been blocked." : "Failed to block access to the folder.");
        });

        allowAccessButton.setOnAction(event -> {
            boolean result = fileAccessControl.allowAccess();
            showAlert(result ? "Access to the folder has been restored." : "Failed to restore access to the folder.");
        });

        unblockSpecificButton.setOnAction(event -> {
            String path = pathField.getText();
            boolean result = fileAccessControl.unblockSpecific(path);
            showAlert(result ? "Access to the specific folder has been restored." : "Failed to restore access to the specific folder.");
        });

        VBox vbox = new VBox(10, blockAccessButton, allowAccessButton, pathField, unblockSpecificButton);
        Scene scene = new Scene(vbox, 400, 200);

        primaryStage.setTitle("File Access Control");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void showAlert(String message) {
        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("Notification");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

