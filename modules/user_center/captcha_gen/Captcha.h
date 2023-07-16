#ifndef _CAPTCAH_GEN_
#define _CAPTCAH_GEN_

#include <opencv2/core.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>

#include <iostream>
#include <string>
#include <vector>

#define IMAGE_H 100
#define IMAGE_W 600
#define CAPTCHA_LEN 12

int generateCaptcha(std::vector<unsigned char> &buffer,
                    std::string &captcha_text);

#endif
