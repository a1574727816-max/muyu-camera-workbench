
    push {r4-r12, lr}
    movw r4, #0
    movt r4, #0x2100
    movw r5, #64
    movw r6, #0x1000
    movt r6, #0x1f22
    movw r8, #0x1000
    movt r8, #0x2180
    movw r10, #0x8320
    movt r10, #0xedb8
    adr r9, state
    ldr r11, [r9]
    add r4, r4, r11
    movw r0, #0x4c46
    movt r0, #0x4853
    str r0, [r8]
    movw r0, #0x4452
    movt r0, #0x2131
    str r0, [r8, #4]
    mov r0, #1024
    str r0, [r8, #12]
next_block:
    str r11, [r8, #8]
    mvn r7, #0
    mov r12, r4
    mov r3, #1024
crc_byte:
    ldrb r0, [r12], #1
    eor r7, r7, r0
    mov r2, #8
crc_bit:
    tst r7, #1
    lsr r7, r7, #1
    eorne r7, r7, r10
    subs r2, r2, #1
    bne crc_bit
    subs r3, r3, #1
    bne crc_byte
    mvn r7, r7
    str r7, [r8, #16]
send_frame:
    mov r12, r8
    mov r3, #20
send_header:
    ldrb r0, [r12], #1
    bl put_byte
    subs r3, r3, #1
    bne send_header
    mov r12, r4
    mov r3, #1024
send_payload:
    ldrb r0, [r12], #1
    bl put_byte
    subs r3, r3, #1
    bne send_payload
wait_ack:
    ldrb r0, [r6, #40]
    tst r0, #1
    beq wait_ack
    ldrb r0, [r6]
    cmp r0, #6
    beq advance
    cmp r0, #27
    beq abort
    b send_frame
advance:
    add r4, r4, #1024
    add r11, r11, #1024
    str r11, [r9]
    cmp r11, #8388608
    beq snapshot_done
    subs r5, r5, #1
    bne next_block
    mov r0, #0
    pop {r4-r12, pc}
snapshot_done:
    mov r0, #0
    str r0, [r9]
    pop {r4-r12, pc}
abort:
    mov r0, #1
    pop {r4-r12, pc}
put_byte:
    ldrb r1, [r6, #40]
    tst r1, #32
    beq put_byte
    strb r0, [r6]
    bx lr
state:
    .word 0
