package com.wheat.ipchecker

import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.os.TestLooperManager
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.launch
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.net.toUri

import com.wheat.ipchecker.ui.theme.IpCheckerTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import androidx.lifecycle.viewmodel.ViewModelInitializer
import coil.compose.rememberAsyncImagePainter
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import kotlinx.coroutines.launch
import okhttp3.ResponseBody
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.io.File
import java.nio.Buffer
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            IpCheckerTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {


                    //ApiScreen()
                    ImageToTextScreen()

                }
            }
        }

    }


    @Composable
    fun CameraCapture(onImageCaptured: (Uri) -> Unit) {
        val context = LocalContext.current
        val launcher = rememberLauncherForActivityResult(ActivityResultContracts.TakePicturePreview()) { bitmap ->
            bitmap?.let {
                val uri = saveImageToCache(context, it)
                onImageCaptured(uri)
            }
        }

        Button(onClick = { launcher.launch() }) {
            Text("Fotoğraf Çek")
        }
    }

    fun saveImageToCache(context: Context, bitmap: Bitmap): Uri {
        val file = File(context.cacheDir, "captured_image.jpg")
        file.outputStream().use {
            bitmap.compress(Bitmap.CompressFormat.JPEG, 100, it)
        }
        return file.toUri()
    }

    fun extractTextFromImage(context: Context, imageUri: Uri, onResult: (List<String>) -> Unit) {
        val recognizer = TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS)
        val image = InputImage.fromFilePath(context, imageUri)

        recognizer.process(image)
            .addOnSuccessListener { visionText ->
                val ipAddresses = extractIPAddresses(visionText.text)
                onResult(ipAddresses)
            }
            .addOnFailureListener {
                onResult(emptyList())
            }
    }

    fun extractIPAddresses(text: String): List<String> {
        val ipRegex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
        return ipRegex.findAll(text).map { it.value }.toList()
    }


    @Composable
    fun ImageToTextScreen() {
        var imageUri by remember { mutableStateOf<Uri?>(null) }
        var extractedIPs by remember { mutableStateOf<List<String>>(emptyList()) }
        var selectedIP by remember { mutableStateOf<String?>(null) }
        var virusTotalResult by remember { mutableStateOf<String?>(null) }
        val context = LocalContext.current

        Column(modifier = Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally) {
            // Kamera Butonu
            CameraCapture { uri ->
                imageUri = uri
                extractTextFromImage(context, uri) { ips ->
                    extractedIPs = ips
                }
            }

            // Seçilen Görseli Göster
            imageUri?.let {
                Image(painter = rememberAsyncImagePainter(it), contentDescription = "Captured Image", modifier = Modifier.size(200.dp))
            }

            Text(text = "Bulunan IP Adresleri:", fontSize = 18.sp, fontWeight = FontWeight.Bold)

            // IP Listesi (Seçilebilir)
            extractedIPs.forEach { ip ->
                Button(
                    onClick = {
                        selectedIP = ip
                        virusTotalResult = "Sorgulanıyor..."
                        checkIPWithVirusTotal(ip) { result ->
                            virusTotalResult = result
                        }
                    },
                    modifier = Modifier.padding(4.dp)
                ) {
                    Text(text = ip)
                }
            }

            // VirusTotal Sonucu
            selectedIP?.let {
                Text(text = "Seçilen IP: $it", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                virusTotalResult?.let { result ->
                    Text(text = "VirusTotal Sonucu: $result", fontSize = 14.sp, color = if (result.startsWith("0/")) Color.Green else Color.Red)
                }
            }

        }
    }


    fun checkIPWithVirusTotal(ip: String, onResult: (String) -> Unit) {
        val client = OkHttpClient()
        val request = Request.Builder()
            .url("https://www.virustotal.com/api/v3/ip_addresses/$ip")
            .get()
            .addHeader("accept", "application/json")
            .addHeader("x-apikey", "****************************************")
            .build()

        thread {
            try {
                val response = client.newCall(request).execute()
                val jsonData = response.body?.string()

                if (jsonData != null) {
                    val jsonObject = JSONObject(jsonData)
                    val attributes = jsonObject.getJSONObject("data").getJSONObject("attributes")

                    val analysisStats = attributes.getJSONObject("last_analysis_stats")

                    // Zararlı olarak işaretlenen motor sayısı
                    val maliciousCount = analysisStats.getInt("malicious")

                    // Toplam analiz eden motor sayısı
                    val totalEngines = analysisStats.getInt("malicious") +
                            analysisStats.getInt("suspicious") +
                            analysisStats.getInt("undetected") +
                            analysisStats.getInt("harmless") +
                            analysisStats.getInt("timeout")

                    // Tags listesini kontrol et, "private" olup olmadığına bak
                    val tagsArray = attributes.optJSONArray("tags")
                    val isPrivate = tagsArray?.let { jsonArray ->
                        (0 until jsonArray.length()).any { jsonArray.getString(it) == "private" }
                    } ?: false

                    // Sonucu oluştur
                    val result = if (isPrivate) {
                        "$maliciousCount/$totalEngines (Private IP)"
                    } else {
                        "$maliciousCount/$totalEngines"
                    }

                    onResult(result)
                } else {
                    onResult("Veri çekilemedi!")
                }
            } catch (e: Exception) {
                onResult("Hata: ${e.message}")
            }
        }
    }




}








