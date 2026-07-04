// Generate canned LC3 frames (16 kHz, 10 ms, 40 B) for the ImpossiBLE Nirva mock:
// 300 tone frames (1 kHz sine, amp 12000) + 100 silence frames, base64 to stdout.
#include <lc3.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void b64(const uint8_t *d, size_t n) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = d[i] << 16 | (i+1 < n ? d[i+1] << 8 : 0) | (i+2 < n ? d[i+2] : 0);
        putchar(t[v >> 18 & 63]); putchar(t[v >> 12 & 63]);
        putchar(i+1 < n ? t[v >> 6 & 63] : '='); putchar(i+2 < n ? t[v & 63] : '=');
    }
}

int main(void) {
    void *mem = malloc(lc3_encoder_size(10000, 16000));
    lc3_encoder_t enc = lc3_setup_encoder(10000, 16000, 0, mem);
    int16_t pcm[160]; uint8_t out[40]; uint8_t tone[300*40], sil[100*40];
    double ph = 0, w = 2*M_PI*1000/16000;
    for (int f = 0; f < 300; f++) {
        for (int i = 0; i < 160; i++) { pcm[i] = (int16_t)(12000*sin(ph)); ph += w; }
        lc3_encode(enc, LC3_PCM_FORMAT_S16, pcm, 1, 40, tone + f*40);
    }
    memset(pcm, 0, sizeof pcm);
    for (int f = 0; f < 100; f++)
        lc3_encode(enc, LC3_PCM_FORMAT_S16, pcm, 1, 40, sil + f*40);
    printf("TONE "); b64(tone, sizeof tone); printf("\nSIL "); b64(sil, sizeof sil); printf("\n");
    return 0;
}
