#include "easy.pb-c.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    Msg msg = MSG__INIT;
    msg.has_id = 1;
    msg.id = 12345;
    msg.name = "Hello, Protobuf-C!";
    msg.has_key = 1;
    uint8_t key_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    msg.key.data = key_data;
    msg.key.len = sizeof(key_data);

    // Serialize the message
    size_t packed_size = msg__get_packed_size(&msg);
    uint8_t *buffer = malloc(packed_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory for buffer\n");
        return EXIT_FAILURE;
    }
    msg__pack(&msg, buffer);

    // Print the serialized data
    printf("Serialized Msg (hex): ");
    for (size_t i = 0; i < packed_size; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    // Unpack the message
    Msg *unpacked_msg = msg__unpack(NULL, packed_size, buffer);
    if (!unpacked_msg) {
        fprintf(stderr, "Failed to unpack message\n");
        free(buffer);
        return EXIT_FAILURE;
    }

    // Print the unpacked message
    printf("Unpacked Msg:\n");
    printf("  ID: %u\n", unpacked_msg->id);
    printf("  Name: %s\n", unpacked_msg->name);
    printf("  Key (hex): ");
    for (size_t i = 0; i < unpacked_msg->key.len; i++) {
        printf("%02X ", unpacked_msg->key.data[i]);
    }
    printf("\n");

    msg__free_unpacked(unpacked_msg, NULL); 
    
    free(buffer);
    return EXIT_SUCCESS;
}