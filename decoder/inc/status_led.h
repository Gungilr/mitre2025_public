/**
 * @file status_led.h
 * @author Samuel Meyers
 * @brief eCTF Status LED Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

 #ifndef __STATUS_LED__
 #define __STATUS_LED__
 
 
 #include "led.h"
 
 /* These macros may be used to control the RGB LED on the MAX78000 fthr boards*/
 
 #define STATUS_LED_OFF(void) printf("STATUS LED: OFF\n");
 #define STATUS_LED_RED(void) printf("STATUS LED: RED\n");
 #define STATUS_LED_GREEN(void) printf("STATUS LED: GREEN\n");
 #define STATUS_LED_BLUE(void) printf("STATUS LED: BLUE\n");
 #define STATUS_LED_PURPLE(void) printf("STATUS LED: PURPLE\n");
 #define STATUS_LED_CYAN(void) printf("STATUS LED: CYAN\n");
 #define STATUS_LED_YELLOW(void) printf("STATUS LED: YELLOW\n");
 #define STATUS_LED_WHITE(void) printf("STATUS LED: WHITE\n");
 
 // Error case alias
 #define STATUS_LED_ERROR STATUS_LED_RED
 
 #endif // __STATUS_LED__
 