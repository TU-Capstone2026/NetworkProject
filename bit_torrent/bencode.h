/*
 * bencode.h - BitTorrent 의 bencode 형식 최소 파서
 *
 *   bencode 형식 (BEP 3)
 *     문자열   : <길이>:<내용>        예) 4:spam
 *     정수     : i<숫자>e             예) i1800e
 *     리스트   : l<값...>e            예) l4:spami3ee
 *     딕셔너리 : d<키><값>...e        예) d1:y1:qe   (키는 문자열, 사전순 정렬)
 *
 *   DHT 메시지, 트래커 응답, 확장 핸드셰이크(BEP 10)가 모두 bencode 딕셔너리다.
 *   패킷이 잘려 있을 수 있으므로 모든 함수는 end 를 넘지 않는지 검사한다.
 */
#ifndef BENCODE_H
#define BENCODE_H

#include <stdint.h>
#include <stddef.h>

/* 값 하나를 건너뛰고 다음 위치를 반환. 형식 오류/잘림이면 NULL */
const uint8_t *bencode_skip(const uint8_t *p, const uint8_t *end, int depth);

/* 문자열 해석: 성공 시 1, s 와 len 에 내용, next 에 다음 위치 */
int bencode_str(const uint8_t *p, const uint8_t *end,
                const uint8_t **s, size_t *len, const uint8_t **next);

/* 정수 해석: 성공 시 1 */
int bencode_int(const uint8_t *p, const uint8_t *end, long long *v, const uint8_t **next);

/* 딕셔너리(p 가 'd')에서 key 의 값 시작 위치를 *val 에. 찾으면 1 */
int bencode_dict_find(const uint8_t *p, const uint8_t *end, const char *key, const uint8_t **val);

/* 편의 함수: 딕셔너리에서 문자열 / 정수 값 바로 꺼내기 */
int bencode_dict_str(const uint8_t *p, const uint8_t *end, const char *key,
                     const uint8_t **s, size_t *len);
int bencode_dict_int(const uint8_t *p, const uint8_t *end, const char *key, long long *v);

#endif /* BENCODE_H */
