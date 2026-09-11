package com.example.sshclient;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.FileProvider;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Properties;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {

    private EditText etTargetIp, etWordlist;
    private TextView tvConsoleLog;
    private Button btnBruteForce, btnInternetAudit, btnWifiWps, btnLoadDefaultWordlist, btnExportReport;
    private StringBuilder currentReport = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etTargetIp = findViewById(R.id.etTargetIp);
        etWordlist = findViewById(R.id.etWordlist);
        tvConsoleLog = findViewById(R.id.tvConsoleLog);
        btnBruteForce = findViewById(R.id.btnBruteForce);
        btnInternetAudit = findViewById(R.id.btnInternetAudit);
        btnWifiWps = findViewById(R.id.btnWifiWps);
        btnLoadDefaultWordlist = findViewById(R.id.btnLoadDefaultWordlist);
        btnExportReport = findViewById(R.id.btnExportReport);

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, 1);
        }

        btnLoadDefaultWordlist.setOnClickListener(v -> loadWordlistFromAssets());

        btnBruteForce.setOnClickListener(v -> {
            String target = etTargetIp.getText().toString().trim();
            String[] passwords = etWordlist.getText().toString().split("\n");
            if(target.isEmpty()) { updateConsole("[-] Erreur: Indiquez une IP cible."); return; }
            updateConsole("[*] Lancement du dictionnaire SSH sur " + target + "...");
            new Thread(() -> runSshAudit(target, "root", passwords)).start();
        });

        btnInternetAudit.setOnClickListener(v -> {
            String target = etTargetIp.getText().toString().trim();
            if(target.isEmpty()) { updateConsole("[-] Erreur: Indiquez un domaine Internet."); return; }
            if (!target.startsWith("http")) target = "https://" + target;
            String finalTarget = target;
            updateConsole("[*] Vérification des mécanismes de protection Internet sur " + finalTarget + "...");
            new Thread(() -> runInternetAudit(finalTarget)).start();
        });

        btnWifiWps.setOnClickListener(v -> {
            updateConsole("[*] Analyse de l'environnement Wi-Fi (Détection WPS/BSSID)...");
            runWifiWpsAudit();
        });

        btnExportReport.setOnClickListener(v -> exportAuditReport());
    }

    private void loadWordlistFromAssets() {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(getAssets().open("wordlist.txt")))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("#") && !line.trim().isEmpty()) {
                    sb.append(line).append("\n");
                }
            }
            etWordlist.setText(sb.toString());
            updateConsole("[+] Dictionnaire réseau chargé avec succès depuis les ressources internes.");
        } catch (IOException e) {
            updateConsole("[-] Erreur lors du chargement de la wordlist d'usine.");
        }
    }

    private void runSshAudit(String host, String username, String[] passwords) {
        JSch jsch = new JSch();
        boolean found = false;
        for (String password : passwords) {
            password = password.trim();
            if (password.isEmpty()) continue;
            try {
                Session session = jsch.getSession(username, host, 22);
                session.setPassword(password);
                Properties config = new Properties();
                config.put("StrictHostKeyChecking", "no");
                session.setConfig(config);
                session.setTimeout(2500);
                session.connect();
                if (session.isConnected()) {
                    String cleanResult = "[!] ALERTE SÉCURITÉ - MOT DE PASSE FAIBLE TROUVÉ :\n-> " + username + " : " + password;
                    updateConsole(cleanResult);
                    session.disconnect();
                    found = true;
                    break;
                }
            } catch (Exception e) {
                // Échec d'authentification normal
            }
        }
        if (!found) updateConsole("[-] Fin de l'audit SSH : Aucun mot de passe vulnérable détecté.");
    }

    private void runInternetAudit(String url) {
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder().url(url).header("User-Agent", "Mozilla/5.0 AuditSuite").build();
        try (Response response = client.newCall(request).execute()) {
            StringBuilder sb = new StringBuilder();
            sb.append("[+] Connexion établie. Code HTTP : ").append(response.code()).append("\n");
            String server = response.header("Server");
            if (server != null) sb.append("[*] Signature Serveur détectée : ").append(server).append("\n");
            if (response.header("X-Protected-By") != null || response.header("X-WAF") != null) {
                sb.append("[+] Pare-feu applicatif (WAF) détecté en frontal.\n");
            } else {
                sb.append("[-] Aucun WAF évident détecté via les en-têtes HTTP de base.\n");
            }
            updateConsole(sb.toString());
        } catch (Exception e) {
            updateConsole("[-] Impossible de joindre l'hôte internet : " + e.getMessage());
        }
    }

    private void runWifiWpsAudit() {
        WifiManager wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            updateConsole("[-] Erreur : Permission de localisation manquante.");
            return;
        }
        List<ScanResult> results = wifiManager.getScanResults();
        if (results == null || results.isEmpty()) {
            updateConsole("[-] Aucun réseau détecté. Activez le Wi-Fi et la Localisation.");
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("[+] Réseaux détectés sous contrat d'audit :\n\n");
        for (ScanResult result : results) {
            sb.append("SSID: ").append(result.SSID).append("\n");
            sb.append("BSSID (Mac): ").append(result.BSSID).append("\n");
            sb.append("Signal: ").append(result.level).append(" dBm\n");
            if (result.capabilities.contains("WPS")) {
                sb.append("--> [VULNÉRABLE] : WPS activé sur cette borne !\n");
            } else {
                sb.append("--> [SÉCURISÉ] : WPS désactivé.\n");
            }
            sb.append("----------------------------------\n");
        }
        updateConsole(sb.toString());
    }

    private void exportAuditReport() {
        String filename = "rapport_audit_reseau.txt";
        File reportFile = new File(getExternalFilesDir(null), filename);
        try (FileOutputStream fos = new FileOutputStream(reportFile)) {
            fos.write(currentReport.toString().getBytes());
            Toast.makeText(this, "Rapport enregistré dans le stockage de l'application", Toast.LENGTH_LONG).show();
            
            Intent intent = new Intent(Intent.ACTION_SEND);
            intent.setType("text/plain");
            intent.putExtra(Intent.EXTRA_STREAM, FileProvider.getUriForFile(this, getPackageName() + ".provider", reportFile));
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(intent, "Partager le rapport d'audit réseau via..."));
        } catch (IOException e) {
            Toast.makeText(this, "Erreur lors de la génération du rapport", Toast.LENGTH_SHORT).show();
        }
    }

    private void updateConsole(String text) {
        currentReport.append("\n").append(text);
        runOnUiThread(() -> tvConsoleLog.setText(text));
    }
}
