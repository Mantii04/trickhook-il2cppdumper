package com.mantii04.il2cppdumper

import java.util.function.Consumer

object NativeBridge {
    init { System.loadLibrary("il2cppdumper") }

    external fun runDumper(
        soPath: String,
        metaPath: String,
        outDir: String,
        logger: Consumer<String>
    ): Int

    external fun version(): String
}
