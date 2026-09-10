package com.example.sshclient;

import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class MainActivity extends AppCompatActivity {

    private EditText editHost, editPort, editUser, editPassword;
    private TextView textOutput;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        editHost = findViewById(R.id.editHost);
        editPort = findViewById(R.id.editPort);
        editUser = findViewById(R.id.editUser);
        editPassword = findViewById(R.id.editPassword);
        textOutput = findViewById(R.id.textOutput);

        Button btnConnect = findViewById(R.id.btnConnect);
        btnConnect.setOnClickListener(v -> {
            String host = editHost.getText().toString().trim();
            String portStr = editPort.getText().toString().trim();
            String user = editUser.getText().toString().trim();
            String password = editPassword.getText().toString();
            int port = portStr.isEmpty() ? 22 : Integer.parseInt(portStr);

            textOutput.setText("Connexion en cours...");

            new Thread(() -> {
                String result = connectAndRun(host, port, user, password, "echo test_connexion_reussie");
                runOnUiThread(() -> textOutput.setText(result));
            }).start();
        });
    }

    private String connectAndRun(String host, int port, String user, String password, String command) {
        Session session = null;
        ChannelExec channel = null;
        try {
            JSch jsch = new JSch();
            session = jsch.getSession(user, host, port);
            session.setPassword(password);

            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(15000);

            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            InputStream in = channel.getInputStream();
            channel.connect();

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] tmp = new byte[1024];
            int n;
            while ((n = in.read(tmp)) != -1) {
                buffer.write(tmp, 0, n);
            }
            String output = buffer.toString().trim();
            return output.isEmpty() ? "Connecté avec succès." : output;

        } catch (Exception e) {
            return "Erreur : " + e.getMessage();
        } finally {
            if (channel != null) channel.disconnect();
            if (session != null) session.disconnect();
        }
    }
  }
