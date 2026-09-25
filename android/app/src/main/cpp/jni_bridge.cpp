#include <jni.h>
#include <string>
#include <android/log.h>
#include "dumper/main.h"

#define LOG_TAG "il2cppdumper"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static std::string jstr(JNIEnv* env, jstring s) {
    if (!s) return {};
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return out;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_mantii04_il2cppdumper_NativeBridge_runDumper(
    JNIEnv* env, jclass,
    jstring soPath, jstring metaPath, jstring outDir, jobject logger)
{
    std::string so = jstr(env, soPath);
    std::string meta = jstr(env, metaPath);
    std::string out = jstr(env, outDir);

    jclass consumerCls = env->GetObjectClass(logger);
    jmethodID acceptMid = env->GetMethodID(consumerCls, "accept", "(Ljava/lang/Object;)V");
    if (!acceptMid) return -1;

    auto emit = [&](const std::string& line) {
        jstring jl = env->NewStringUTF(line.c_str());
        env->CallVoidMethod(logger, acceptMid, jl);
        env->DeleteLocalRef(jl);
    };

    LOGI("runDumper so=%s meta=%s out=%s", so.c_str(), meta.c_str(), out.c_str());
    return run_dump(so, meta, out, emit);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_mantii04_il2cppdumper_NativeBridge_version(JNIEnv* env, jclass) {
    return env->NewStringUTF("1.0-native");
}
