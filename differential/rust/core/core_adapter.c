// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

/* A bounded, one-request process. No fixture expectations enter this adapter. */
#include <tlv/builtins/asn1/ber.h>
#include <tlv/builtins/asn1/der_validation.h>
#include <tlv/format.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t offset, size, tag_size, value_offset, value_size, depth;
    uint64_t number;
    unsigned tag_class, constructed;
} node_t;
static node_t nodes[256];
static size_t count;
static const uint8_t *input;
static const char *category, *stage = "framing", *source = "library";
static tlv_result_t native;

static int fail(tlv_result_t result, int bounded)
{
    native = result;
    if (result == TLV_ERR_OUT_OF_MEMORY) exit(2);
    switch (result) {
    case TLV_ERR_TRUNCATED: category = bounded ? "invalid" : "truncated"; break;
    case TLV_ERR_INVALID_TAG: case TLV_ERR_INVALID_TAG_SIZE:
    case TLV_ERR_INVALID_LENGTH: category = "invalid"; break;
    case TLV_ERR_INVALID_VALUE: category = "invalid"; stage = "contents"; break;
    case TLV_ERR_LIMIT: category = "limit"; stage = "policy"; break;
    default: category = "unknown"; stage = "unknown"; break;
    }
    return 0;
}

static int walk(const tlv_format_t *format, const uint8_t *data, size_t size,
                size_t depth, int bounded, size_t *consumed)
{
    tlv_decoded_t decoded;
    tlv_format_error_t error;
    tlv_result_t result;
    node_t *node;
    size_t position = 0;
    if (depth > 16 || count == 256) {
        source = "policy";
        return fail(TLV_ERR_LIMIT, 0);
    }
    result = tlv_format_decode(format, data, size, &decoded, &error);
    if (result != TLV_OK) return fail(result, bounded);
    node = &nodes[count++];
    node->offset = (size_t)(data - input);
    node->size = decoded.source.size;
    node->tag_size = decoded.element.tag.size;
    node->value_offset = (size_t)(decoded.element.value.data - input);
    node->value_size = (size_t)decoded.element.value.size;
    node->depth = depth;
    node->tag_class = decoded.element.tag.data[0] >> 6;
    node->constructed = (decoded.element.tag.data[0] & 32) != 0;
    result = tlv_ber_tag_number(&decoded.element.tag, &node->number);
    if (result != TLV_OK) return fail(result, bounded);
    if (node->constructed) {
        while (position < node->value_size) {
            size_t child_size = 0;
            /* A complete parent's value is a hard boundary, even if indefinite. */
            if (!walk(format, decoded.element.value.data + position,
                      node->value_size - position, depth + 1, 1, &child_size)) return 0;
            if (!child_size) exit(2);
            position += child_size;
        }
    }
    *consumed = node->size;
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t data[4096];
    size_t size, i, consumed = 0;
    int der, ok = 1;
    if (argc != 3 || (strcmp(argv[1], "ber") && strcmp(argv[1], "der"))) return 2;
    der = !strcmp(argv[1], "der");
    size = strlen(argv[2]);
    if (size % 2 || size > sizeof(data) * 2) return 2;
    size /= 2;
    for (i = 0; i < size; ++i) {
        char pair[3] = {argv[2][2*i], argv[2][2*i+1], 0}, *end;
        unsigned long value = strtoul(pair, &end, 16);
        if (*end || strspn(pair, "0123456789abcdef") != 2) return 2;
        data[i] = (uint8_t)value;
    }
    input = data;
    if (!size) { category = "empty"; source = "adapter"; stage = "policy"; ok = 0; }
    if (ok && der) {
        tlv_element_t element;
        tlv_der_limits_t limits = {16, 4096, 4096, 256};
        tlv_result_t result = tlv_der_read_strict(data, size, &limits, &element, &consumed, NULL);
        if (result != TLV_OK) ok = fail(result, 0);
    }
    if (ok) ok = walk(der ? &tlv_format_der : &tlv_format_ber, data, size, 0, 0, &consumed);
    if (ok && consumed != size) {
        category = "trailing"; source = "adapter"; stage = "policy"; ok = 0;
    }
    if (!ok) {
        printf("{\"result\":\"reject\",\"error\":{\"category\":\"%s\",\"source\":\"%s\","
               "\"stage\":\"%s\",\"native_code\":", category, source, stage);
        if (native) printf("\"%d: %s\"", (int)native, tlv_result_string(native));
        else printf("null");
        puts(",\"offset\":null}}");
        return 0;
    }
    printf("{\"result\":\"accept\",\"consumed\":%zu,\"nodes\":[", consumed);
    for (i = 0; i < count; ++i) {
        const node_t *n = &nodes[i];
        printf("%s{\"offset\":%zu,\"size\":%zu,\"tag_size\":%zu,\"value_offset\":%zu,"
               "\"value_size\":%zu,\"depth\":%zu,\"number\":\"%" PRIu64 "\","
               "\"class\":%u,\"constructed\":%s}", i ? "," : "", n->offset, n->size,
               n->tag_size, n->value_offset, n->value_size, n->depth, n->number,
               n->tag_class, n->constructed ? "true" : "false");
    }
    puts("]}");
    return 0;
}
