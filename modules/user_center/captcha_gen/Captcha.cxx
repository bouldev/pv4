#include "Captcha.h"
#include <algorithm>
#include <iostream>
#include <opencv2/core.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>
#include <random>
#include <string>
#include <vector>

#define NUMBER 10

using namespace cv;
using namespace std;

static std::string getRandomString(size_t n);

static int getRandomNumber(int l, int h);

static int drawingRandomLines(Mat &image);

static int drawingRandomText(Mat &image);

static int drawingCaptchaText(Mat &image, const string &captcha_text);

static Scalar randomColor();

string getRandomString(size_t n) {
  static auto random = [] {
    static const std::string alphabets =
        "0123456789abcdefghijklmnopqrstuivwxyz";
    static std::mt19937 gen(std::random_device{}());
    static std::uniform_int_distribution<> distrib(0, alphabets.size() - 1);
    return [] { return alphabets[distrib(gen)]; };
  }();

  std::string randomString(n, '\0');
  std::transform(randomString.begin(), randomString.end(), randomString.begin(),
                 [](auto c) { return random(); });
  return randomString;
}

int getRandomNumber(int l, int h) {

  static std::mt19937 gen(std::random_device{}());
  std::uniform_int_distribution<int> distrib(l, h);
  return distrib(gen);
}

int generateCaptcha(std::vector<unsigned char> &buffer, string &captcha_text) {
  buffer = {};
  captcha_text = "";
  try {
    string text = getRandomString(CAPTCHA_LEN);
    captcha_text = text;

    Mat image = Mat::zeros(IMAGE_H, IMAGE_W, CV_8UC3);
    drawingRandomLines(image);
    drawingRandomText(image);
    drawingCaptchaText(image, text);
    cv::Mat finalImage;
    cv::resize(image, finalImage, cv::Size(300,50), 0,0,cv::INTER_AREA);
    cv::imencode(".png", finalImage, buffer);

  } catch (const std::exception &ex) {
    std::cout << ex.what() << std::endl;
    return -1;
  }
  return 0;
}
int drawingRandomLines(Mat &image) {
  Point pt1, pt2;
  static const int lineType = 8;
  static const int x_1 = 1;
  static const int y_1 = 1;
  static const int x_2 = IMAGE_W;
  static const int y_2 = IMAGE_H;

  for (int i = 0; i < NUMBER; i++) {
    pt1.x = getRandomNumber(x_1, x_2);
    pt1.y = getRandomNumber(y_1, y_2);
    pt2.x = getRandomNumber(x_1, x_2);
    pt2.y = getRandomNumber(y_1, y_2);
    line(image, pt1, pt2, randomColor(), getRandomNumber(1, 8), 8);
  }
  return 0;
}
int drawingRandomText(Mat &image) {
  string text = getRandomString(5);
  static const int lineType = 8;
  static const int x_1 = 1;
  static const int y_1 = 1;
  static const int x_2 = IMAGE_W;
  static const int y_2 = IMAGE_H;

  for (int i = 1; i < NUMBER; i++) {
    Point org;
    org.x = getRandomNumber(x_1, x_2);
    org.y = getRandomNumber(y_1, y_2 / 2);
    putText(image, text, org, getRandomNumber(0, 7),
            getRandomNumber(0, 100) * 0.05 + 0.1, randomColor(),
            getRandomNumber(1, 3), lineType);
  }
  return 0;
}

int drawingCaptchaText(Mat &image, const string &captcha_text) {
  static const int lineType = 8;
  string text = captcha_text;
  Size textsize = getTextSize(text, FONT_HERSHEY_COMPLEX, 2, 2, 0);
  Point org((IMAGE_W - textsize.width) / 2,
            ((IMAGE_H - textsize.height) / 2) + (textsize.height / 2));
  Mat image2;
  for (int i = 0; i < 255; i += 2) {
    image2 = image - Scalar::all(i);
    putText(image2, text, org, FONT_HERSHEY_COMPLEX, 2,
            Scalar(i, i, getRandomNumber(155, 200)), 2, lineType);
  }
  cv::Mat matE;
  cv::addWeighted(image2, 1.0, image, 1.0, 0.0, matE);
  matE.copyTo(image);
  return 0;
}

Scalar randomColor() {
  int icolor = (int)getRandomNumber(1, 65535);
  return Scalar(icolor & 255, (icolor >> 8) & 255, (icolor >> 16) & 255);
}
