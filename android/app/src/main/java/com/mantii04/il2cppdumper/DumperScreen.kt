package com.mantii04.il2cppdumper

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.function.Consumer

private data class Slot(val path: String?, val label: String)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DumperScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var so by remember { mutableStateOf<Slot?>(null) }
    var meta by remember { mutableStateOf<Slot?>(null) }
    var outDir by remember { mutableStateOf<String?>(null) }
    var log by remember { mutableStateOf("ready — pick the two files and an output folder.\n") }
    var running by remember { mutableStateOf(false) }
    val scroll = rememberScrollState()

    fun append(s: String) {
        log = log + s + "\n"
    }

    fun ensureAllFiles() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            try {
                val i = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                i.data = Uri.parse("package:${ctx.packageName}")
                ctx.startActivity(i)
            } catch (_: Exception) {
                ctx.startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
            }
        }
    }

    LaunchedEffect(Unit) { ensureAllFiles() }

    val pickSo = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        r.data?.data?.let { uri ->
            scope.launch {
                val f = copyToCache(ctx, uri, "libil2cpp.so")
                withContext(Dispatchers.Main) { so = Slot(f.absolutePath, "${f.name} • ${f.length()/1024/1024} MB") }
            }
        }
    }
    val pickMeta = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        r.data?.data?.let { uri ->
            scope.launch {
                val f = copyToCache(ctx, uri, "global-metadata.dat")
                withContext(Dispatchers.Main) { meta = Slot(f.absolutePath, "${f.name} • ${f.length()/1024} KB") }
            }
        }
    }
    val pickOut = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        uri?.let {
            val path = treeUriToPath(ctx, it) ?: run {
                Toast.makeText(ctx, "cannot resolve output path", Toast.LENGTH_SHORT).show()
                return@let
            }
            File(path).mkdirs()
            outDir = path
        }
    }

    fun pickFile(launcher: androidx.activity.result.ActivityResultLauncher<Intent>, mime: String) {
        val i = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = mime
            putExtra("android.provider.extra.INITIAL_URI",
                Uri.parse("content://com.android.externalstorage.documents/root/primary"))
        }
        launcher.launch(i)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Il2CppDumper", fontFamily = FontFamily.Monospace) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer
                )
            )
        }
    ) { pad ->
        Column(
            Modifier.padding(pad).fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            FileCard(
                title = "libil2cpp.so",
                slot = so,
                onClick = { pickFile(pickSo, "*/*") }
            )
            FileCard(
                title = "global-metadata.dat",
                slot = meta,
                onClick = { pickFile(pickMeta, "*/*") }
            )
            FileCard(
                title = "output folder",
                slot = outDir?.let { Slot(it, it) },
                onClick = { pickOut.launch(null) },
                isDir = true
            )

            Button(
                onClick = {
                    val s = so?.path ?: return@Button
                    val m = meta?.path ?: return@Button
                    val o = outDir ?: return@Button
                    running = true
                    log = ""
                    append("─── dumping ───")
                    scope.launch {
                        val code = withContext(Dispatchers.IO) {
                            NativeBridge.runDumper(s, m, o, Consumer { line ->
                                scope.launch(Dispatchers.Main) { append(line) }
                            })
                        }
                        running = false
                        append("─── exit $code ───")
                        if (code == 0) append("output: $o")
                    }
                },
                enabled = so != null && meta != null && outDir != null && !running,
                modifier = Modifier.fillMaxWidth().height(56.dp),
                shape = RoundedCornerShape(16.dp)
            ) {
                if (running) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(22.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.dp
                    )
                    Spacer(Modifier.width(12.dp))
                    Text("running…")
                } else {
                    Icon(Icons.Default.PlayArrow, null)
                    Spacer(Modifier.width(8.dp))
                    Text("run dumper", fontSize = 16.sp)
                }
            }

            Box(
                Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .background(
                        Brush.verticalGradient(listOf(Color(0xFF0A0E14), Color(0xFF111827))),
                        RoundedCornerShape(16.dp)
                    )
            ) {
                Text(
                    text = log,
                    color = Color(0xFF7DD3FC),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(scroll)
                        .padding(12.dp)
                )
            }
        }
    }
}

@Composable
private fun FileCard(title: String, slot: Slot?, onClick: () -> Unit, isDir: Boolean = false) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh)
    ) {
        Row(
            Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                if (isDir) Icons.Default.Folder else Icons.Default.InsertDriveFile,
                null,
                tint = if (slot != null) MaterialTheme.colorScheme.primary
                       else MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(
                    slot?.label ?: "tap to select",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1
                )
            }
            if (slot != null) Icon(Icons.Default.CheckCircle, null, tint = MaterialTheme.colorScheme.primary)
            else Icon(Icons.Default.ChevronRight, null)
        }
    }
}

private fun copyToCache(ctx: android.content.Context, uri: Uri, name: String): File {
    val dir = File(ctx.cacheDir, "picked").apply { mkdirs() }
    val out = File(dir, name)
    ctx.contentResolver.openInputStream(uri)!!.use { i ->
        out.outputStream().use { o -> i.copyTo(o, 64 * 1024) }
    }
    return out
}

private fun treeUriToPath(ctx: android.content.Context, uri: Uri): String? {
    val docId = androidx.documentfile.provider.DocumentFile.fromTreeUri(ctx, uri)
        ?.uri?.lastPathSegment ?: return null
    val split = docId.split(":")
    if (split.size < 2) return null
    val type = split[0]
    val rel = split[1]
    return when (type) {
        "primary" -> "${Environment.getExternalStorageDirectory()}/$rel"
        "raw" -> rel
        else -> "/storage/$type/$rel"
    }
}
