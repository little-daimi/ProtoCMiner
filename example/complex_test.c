#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// 引入 protobuf-c 编译器生成的头文件
#include "complex.pb-c.h"

int main() {
    // 初始化主结构体
    Ctf__Test__UserRecord record = CTF__TEST__USER_RECORD__INIT;
    Ctf__Test__UserRecord__Session session = CTF__TEST__USER_RECORD__SESSION__INIT;
    Ctf__Test__Configuration config = CTF__TEST__CONFIGURATION__INIT;

    // 填充数据 (强迫编译器保留所有结构体的引用)
    record.user_id = 0xDEADBEEF;
    record.username = "admin_reverse_engineer";
    
    record.has_status = 1;
    record.status = CTF__TEST__GLOBAL_STATUS__STATUS_ACTIVE;
    
    record.has_role = 1;
    record.role = CTF__TEST__USER_RECORD__ROLE__ROLE_SUPERADMIN;

    // 填充 Session
    session.session_token = "token-1337-pwn";
    session.expire_time = 999999999;
    session.has_is_active = 1;
    session.is_active = 1;
    
    // 填充 Config
    config.max_retries = 5;
    config.has_timeout_sec = 1;
    config.timeout_sec = 3.14159f;

    // 构建嵌套关系
    session.session_config = &config;

    record.n_active_sessions = 1;
    Ctf__Test__UserRecord__Session *sessions[1] = {&session};
    record.active_sessions = sessions;

    record.easter_egg = "You found the magic descriptor!";

    // 序列化 (Pack)
    size_t len = ctf__test__user_record__get_packed_size(&record);
    uint8_t *buf = malloc(len);
    if (!buf) {
        return 1;
    }
    ctf__test__user_record__pack(&record, buf);

    // 打印信息，确保符号表和描述符被编译进二进制文件
    printf("[+] Packed protobuf size: %zu bytes\n", len);
    printf("[+] Main Descriptor Name: %s\n", ctf__test__user_record__descriptor.name);
    printf("[+] Nested Enum Name: %s\n", ctf__test__user_record__role__descriptor.name);
    
    // 写入文件（可选，用来看看纯二进制长啥样）
    FILE *f = fopen("output.bin", "wb");
    if (f) {
        fwrite(buf, 1, len, f);
        fclose(f);
    }

    free(buf);
    return 0;
}