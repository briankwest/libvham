/* libvham/src/causes.c — cause/status code dictionary.
 *
 * Generated from GetCauseStr @ 0x263164 in libsvcapi. Update by
 * re-running the extractor script when the binary changes.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>

#include "vham/causes.h"

static const vham_cause_t VHAM_CAUSES[] = {
    { 0x0000, "ok", "错误0" },
    { 0x0001, "unallocated number", "未分配号码" },
    { 0x0002, "no route to destination", "无目的路由" },
    { 0x0003, "user busy", "用户忙" },
    { 0x0004, "no user answer", "用户无应答(人不应答)" },
    { 0x0005, "call rejected", "呼叫被拒绝" },
    { 0x0006, "route error", "路由错误" },
    { 0x0007, "device rejected", "设备拒绝" },
    { 0x0008, "request from wrong ip", "错误IP地址过来的业务请求" },
    { 0x0009, "normal, unspecified", "通常,未指定" },
    { 0x000a, "temporary error", "临时错误" },
    { 0x000b, "resource unavailable", "资源不可用" },
    { 0x000c, "invalid call reference", "不正确的呼叫参考号" },
    { 0x000d, "mandatory ie missing", "必选信息单元丢失" },
    { 0x000e, "timer expired", "定时器超时" },
    { 0x000f, "rejected by user", "被用户拒绝" },
    { 0x0010, "callee stopped", "被叫停止" },
    { 0x0011, "user not found", "用户不存在" },
    { 0x0012, "no access", "不可接入" },
    { 0x0013, "user offline", "用户关机" },
    { 0x0014, "forced release", "强制拆线" },
    { 0x0015, "handover release", "切换拆线" },
    { 0x0016, "call collision", "呼叫冲突" },
    { 0x0017, "temporarily unreachable", "暂时无法接通" },
    { 0x0018, "auth error", "鉴权错误" },
    { 0x0019, "auth required", "需要鉴权" },
    { 0x001a, "sdp negotiation error", "SDP选择错误" },
    { 0x001b, "media resource error", "媒体资源错误" },
    { 0x001c, "internal error", "内部错误" },
    { 0x001d, "priority too low", "优先级不够" },
    { 0x001e, "service conflict", "业务冲突" },
    { 0x001f, "service-driven retry", "由于业务要求,不释放,启动重呼定时器" },
    { 0x0020, "call not found", "呼叫不存在" },
    { 0x0021, "duplicate registration", "重复注册" },
    { 0x0022, "media gw offline", "MG离线" },
    { 0x0023, "dispatcher hung up", "调度员要求退出呼叫" },
    { 0x0024, "database error", "数据库操作错误" },
    { 0x0025, "too many users", "用户数太多" },
    { 0x0026, "duplicate user number", "相同的用户号码" },
    { 0x0027, "duplicate fixed ip", "相同的固定IP地址" },
    { 0x0028, "parameter error", "参数错误" },
    { 0x0029, "duplicate group number", "相同的组号码" },
    { 0x002a, "too many groups", "太多的组" },
    { 0x002b, "no such group", "没有这个组" },
    { 0x002c, "duplicate user name", "相同的用户名字" },
    { 0x002d, "oam operation error", "OAM操作错误" },
    { 0x002e, "invalid address format", "不正确的地址格式" },
    { 0x002f, "dns/ip error", "DNS或IP地址错误" },
    { 0x0030, "unsupported service", "不支持的业务" },
    { 0x0031, "no media data", "没有媒体数据" },
    { 0x0032, "retry call", "重新呼叫" },
    { 0x0033, "link broken", "断链" },
    { 0x0034, "org permission denied", "组织越权" },
    { 0x0035, "duplicate org number", "相同的组织号码" },
    { 0x0036, "duplicate org name", "相同的组织名字" },
    { 0x0037, "unallocated org number", "未分配的组织号码" },
    { 0x0038, "in another org", "在其他组织中" },
    { 0x0039, "group call already active", "已经有组呼存在" },
    { 0x003a, "conference already active", "已经有会议存在" },
    { 0x003b, "wrong segment format", "错误的号段格式" },
    { 0x003c, "", "用户号码段冲突" },
    { 0x003d, "", "组号码段冲突" },
    { 0x003e, "", "不在号段内" },
    { 0x003f, "", "用户所在组太多" },
    { 0x0040, "", "调度台号段冲突" },
    { 0x0041, "", "外网用户" },
    { 0x0042, "", "无条件呼叫前转" },
    { 0x0043, "", "遇忙呼叫前转" },
    { 0x0044, "", "不可及呼叫前转" },
    { 0x0045, "", "无应答呼叫前转" },
    { 0x0046, "", "最大前转次数" },
    { 0x0047, "", "OAM操作无权限" },
    { 0x0048, "", "号码错误" },
    { 0x0049, "", "资源不足" },
    { 0x004a, "", "组织到期" },
    { 0x004b, "", "用户到期" },
    { 0x004c, "", "相同的路由名字" },
    { 0x004d, "", "未分配的路由" },
    { 0x004e, "", "OAM消息前转" },
    { 0x004f, "", "未配置主号码" },
    { 0x0050, "", "组中没有用户" },
    { 0x0051, "", "用户锁定在其他组" },
    { 0x0052, "", "组中没有在线用户" },
    { 0x0053, "", "注册前转" },
    { 0x0054, "", "协议错误" },
    { 0x0055, "", "无业务权限" },
    { 0x0056, "", "阻塞" },
    { 0x0057, "", "用户使用终端,停止监听" },
    { 0x0058, "", "错误的制造商" },
    { 0x0059, "", "网关强制拆线" },
    { 0x005a, "", "太多的在线终端数" },
    { 0x005b, "", "RTP链路无数据检测超时" },
    { 0x005c, "", "触发SOS业务释放" },
    { 0x005d, "", "遥晕引起业务中断" },
    { 0x005e, "", "用户自主控制的呼叫前传" },
};

#define N_CAUSES (sizeof VHAM_CAUSES / sizeof VHAM_CAUSES[0])

const vham_cause_t *vham_cause_lookup(uint16_t code) {
    for (unsigned i = 0; i < N_CAUSES; ++i)
        if (VHAM_CAUSES[i].code == code) return &VHAM_CAUSES[i];
    return NULL;
}

const char *vham_cause_name(uint16_t code) {
    const vham_cause_t *c = vham_cause_lookup(code);
    if (c && c->name_en && *c->name_en) return c->name_en;
    return "unknown";
}
