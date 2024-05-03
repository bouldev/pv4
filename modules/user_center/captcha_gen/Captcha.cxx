#include "Captcha.h"
#include <algorithm>
#include <iostream>
#include <opencv2/core.hpp>
#include <opencv2/freetype.hpp>
#include <opencv2/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>
#include <random>
#include <string>
#include <vector>
#include "utils.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "cpp-httplib/httplib.h"


#define NUMBER 10

using namespace cv;
using namespace std;

static std::string getRandomString(size_t n);

static int getRandomNumber(int l, int h);

static int drawingRandomLines(Mat &image);

static int drawingRandomText(Mat &image);

static int drawingCaptchaText(Mat &image, string& output);

static Scalar randomColor();

string getRandomString(size_t n) {
  static auto random = [] {
    static const std::string alphabets =
        "23456789abcdefghijkmnpqrstuivwxyz";
    static std::mt19937 gen(std::random_device{}());
    static std::uniform_int_distribution<> distrib(0, alphabets.size() - 1);
    return [] { return alphabets[distrib(gen)]; };
  }();

  std::string randomString(n, '\0');
  std::transform(randomString.begin(), randomString.end(), randomString.begin(),
                 [](auto c) { return random(); });
  return randomString;
}


string getRandomNumberString(size_t n) {
  static auto random = [] {
    static const std::string alphabets =
        "0123456789";
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
	  Mat image;
	  httplib::Client rdClient("https://random.dog");
	  while(true) {
		  auto woof=rdClient.Get("/woof.json");
		  Json::Value woofJson;
		  if(!Utils::parseJSON(woof->body, &woofJson)) {
			image=Mat::zeros(600, 600, CV_8UC3);
			break;
		  }
		  const std::regex wurl_regex("https:\\/\\/random\\.dog(\\/.+\\.jpg)$");
		  std::smatch wmatch;
		  std::string image_url=woofJson["url"].asString();
		  if(!std::regex_match(image_url, wmatch, wurl_regex))
			  continue;
		  auto dogImage=rdClient.Get(wmatch[1].str());
		  std::vector<unsigned char> body_vec(dogImage->body.begin(), dogImage->body.end());
		  Mat fullImage=cv::imdecode(body_vec, -1);
		  cv::resize(fullImage, image, cv::Size(600, 600), 0, 0, cv::INTER_AREA);
		  break;
	  }
    //Mat image = Mat::zeros(IMAGE_H, IMAGE_W, CV_8UC3);
    //Mat image=Mat::zeros(600, 600, CV_8UC3);
    //drawingRandomLines(image);
    //drawingRandomText(image);
    std::string text;
    drawingCaptchaText(image, text);
    captcha_text = text;
    cv::Mat finalImage;
    cv::resize(image, finalImage, cv::Size(300,300), 0,0,cv::INTER_AREA);
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

std::vector<std::pair<int, Point>> drawThingsInCircle(Mat &image, std::vector<std::string> const& subjects) {
	int ct_index=0;
	int ct_len=subjects.size();
	int radius=getRandomNumber(230, 280);
	std::vector<std::pair<int, Point>> ret_q1;
	std::vector<std::pair<int, Point>> ret_q2;
	std::vector<std::pair<int, Point>> ret_q3;
	std::vector<std::pair<int, Point>> ret_q4;
	for(int i=0;i<radius;i+=60) {
		int first_quadrant_val=sqrt(radius*radius-i*i);
		{
			Point cur_org(300+i, 300+first_quadrant_val);
			ret_q1.push_back(std::make_pair(ct_index,cur_org));
			putText(image, subjects[ct_index], cur_org, FONT_HERSHEY_COMPLEX, getRandomNumber(1.5,2.5), Scalar(getRandomNumber(100, 255),getRandomNumber(100, 255),getRandomNumber(100, 255)), 2, 8);
			ct_index++;
			if(ct_index>=ct_len) {
				break;
			}
		}
		if(first_quadrant_val!=0) {
			Point cur_org(300+i, 300-first_quadrant_val);
			ret_q2.push_back(std::make_pair(ct_index, cur_org));
			putText(image, subjects[ct_index], cur_org, FONT_HERSHEY_COMPLEX, getRandomNumber(1.5,2.5), Scalar(getRandomNumber(100, 255),getRandomNumber(100, 255),getRandomNumber(100, 255)), 2, 8);
			ct_index++;
			if(ct_index==ct_len) {
				break;
			}
		}
		if(i!=0) {
			Point cur_org(300-i, 300+first_quadrant_val);
			ret_q3.push_back(std::make_pair(ct_index, cur_org));
			putText(image, subjects[ct_index], cur_org, FONT_HERSHEY_COMPLEX, getRandomNumber(1.5,2.5), Scalar(getRandomNumber(100, 255),getRandomNumber(100, 255),getRandomNumber(100, 255)), 2, 8);
			ct_index++;
			if(ct_index==ct_len) {
				break;
			}
		}
		if(first_quadrant_val!=0&&i!=0) {
			Point cur_org(300-i, 300-first_quadrant_val);
			ret_q4.push_back(std::make_pair(ct_index, cur_org));
			putText(image, subjects[ct_index], cur_org, FONT_HERSHEY_COMPLEX, getRandomNumber(1.5,2.5), Scalar(getRandomNumber(100, 255),getRandomNumber(100, 255),getRandomNumber(100, 255)), 2, 8);
			ct_index++;
			if(ct_index==ct_len) {
				break;
			}
		}
	}
	std::reverse(ret_q4.begin(), ret_q4.end());
	std::reverse(ret_q1.begin(), ret_q1.end());
	std::vector<std::pair<int, Point>> ret=ret_q4;
	ret.insert(ret.end(), ret_q2.begin(), ret_q2.end());
	ret.insert(ret.end(), ret_q1.begin(), ret_q1.end());
	ret.insert(ret.end(), ret_q3.begin(), ret_q3.end());
	return ret;
}

std::vector<int> drawSubjects(Mat &image, std::vector<std::pair<int, Point>> const& subjects, int rate=5, int x_offset=0) {
	std::vector<int> ret;
	Point center(300, 300);
	for(std::pair<int, Point> const& i:subjects) {
		if(getRandomNumber(0,9)>=rate) {
			continue;
		}
		float x_diff=i.second.x-center.x;
		float y_diff=i.second.y-center.y;
		Point val(center.x+x_offset*20+x_diff*0.8, center.y+10+y_diff*0.8);
		arrowedLine(image, Point(300,300), val, Scalar(getRandomNumber(100, 255), getRandomNumber(100, 255), getRandomNumber(100, 255)), 6, 8);
		ret.push_back(i.first);
	}
	return ret;
}

int drawingCaptchaText(Mat &image, string& output_text) {
	cv::Ptr<cv::freetype::FreeType2> ft2=cv::freetype::createFreeType2();
	ft2->loadFontData("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 0);
	int pattern=getRandomNumber(0,1);
	if(pattern) {
		std::string rand_str=getRandomString(40);
		std::vector<std::string> rand_str_vec(rand_str.size());
		for(int i=0;i<rand_str.size();i++) {
			rand_str_vec[i]=rand_str.substr(i,1);
		}
		std::vector<std::pair<int, Point>> result=drawThingsInCircle(image, rand_str_vec);
		std::vector<int> atari=drawSubjects(image, result);
		std::string str_result;
		if(getRandomNumber(0,1)) {
			std::reverse(atari.begin(), atari.end());
			for(int i:atari) {
				str_result+=rand_str[i];
			}
			arrowedLine(image, Point(20,270), Point(20,310), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(40,270), Point(40,310), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(60,270), Point(60,310), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(80,270), Point(80,310), Scalar(0, 0, 255), 6);
			ft2->putText(image, "请逆时针输入", Point(180, 250), 40, Scalar(0, 0, 255), 2, 8, true);
		}else{
			for(int i:atari) {
				str_result+=rand_str[i];
			}
			arrowedLine(image, Point(20,310), Point(20,270), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(40,310), Point(40,270), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(60,310), Point(60,270), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(80,310), Point(80,270), Scalar(0, 0, 255), 6);
			ft2->putText(image, "请顺时针输入", Point(180, 250), 40, Scalar(0, 0, 255), 2, 8, true);
		}
		ft2->putText(image, "从红色箭头开始", Point(180, 300), 40, Scalar(0, 0, 255), 2, 8, true);
		ft2->putText(image, "所有被中心箭头", Point(180, 350), 40, Scalar(0, 0, 255), 2, 8, true);
		ft2->putText(image, "指向的字母或数字", Point(180, 400), 40, Scalar(0, 0, 255), 2, 8, true);
		output_text=str_result;
	}else {
		std::vector<std::string> rand_str_vec;
		for(int i=0;i<30;i++) {
			rand_str_vec.push_back(getRandomNumberString(2));
		}
		std::vector<std::pair<int, Point>> result=drawThingsInCircle(image, rand_str_vec);
		std::vector<int> atari=drawSubjects(image, result, 3, 1);
		int resulti=0;
		for(int i:atari) {
			resulti+=std::stoi(rand_str_vec[i]);
		}
		ft2->putText(image, "请输入", Point(180, 250), 40, Scalar(0, 0, 255), 2, 8, true);
		ft2->putText(image, "所有被中心箭头", Point(180, 300), 40, Scalar(0, 0, 255), 2, 8, true);
		ft2->putText(image, "指向的数字之和", Point(180, 350), 40, Scalar(0, 0, 255), 2, 8, true);
		if(getRandomNumber(0,1)) {
			resulti= -resulti;
			ft2->putText(image, "的相反数", Point(180, 400), 40, Scalar(0, 0, 255), 2, 8, true);
		}
		output_text=std::to_string(resulti);
	}
	return 0;
#if 0
	std::string captcha_text=pattern?getRandomString(60):getRandomNumberString(60);
	int ct_index=0;
	int ct_len=captcha_text.length();
	std::vector<Point> atari;
	std::string atari_set_q1;
	std::string atari_set_q2;
	std::string atari_set_q3;
	std::string atari_set_q4;
	int radius=getRandomNumber(100, 280);
	for(int i=0;i<radius;i+=60) {
		int first_quadrant_val=sqrt(radius*radius-i*i);
		{
			Point cur_org(300+i, 300+first_quadrant_val);
			if(getRandomNumber(0,10)>=6) {
				atari.push_back(cur_org);
				atari_set_q1+=captcha_text[ct_index];
			}
			putText(image, pattern?captcha_text.substr(ct_index, 1):captcha_text.substr(ct_index*3, 3), cur_org, FONT_HERSHEY_COMPLEX, getRandomNumber(1.5,2.5), Scalar(getRandomNumber(100, 255),getRandomNumber(100, 255),getRandomNumber(100, 255)), 2, 8);
			ct_index++;
			if(ct_index>=ct_len) {
				break;
			}
		}
		if(first_quadrant_val!=0) {
			Point cur_org(300+i, 300-first_quadrant_val);
			if(getRandomNumber(0,10)>=6) {
				atari.push_back(cur_org);
				atari_set_q2+=captcha_text[ct_index];
			}
			putText(image, pattern?captcha_text.substr(ct_index, 1):captcha_text.substr(ct_index*3, 3), cur_org, FONT_HERSHEY_COMPLEX, getRandomNumber(1.5,2.5), Scalar(getRandomNumber(100, 255),getRandomNumber(100, 255),getRandomNumber(100, 255)), 2, 8);
			ct_index++;
			if(ct_index==ct_len) {
				break;
			}
		}
		if(i!=0) {
			Point cur_org(300-i, 300+first_quadrant_val);
			if(getRandomNumber(0,10)>=6) {
				atari.push_back(cur_org);
				atari_set_q3+=captcha_text[ct_index];
			}
			putText(image, pattern?captcha_text.substr(ct_index, 1):captcha_text.substr(ct_index*3, 3), cur_org, FONT_HERSHEY_COMPLEX, getRandomNumber(1.5,2.5), Scalar(getRandomNumber(100, 255),getRandomNumber(100, 255),getRandomNumber(100, 255)), 2, 8);
			ct_index++;
			if(ct_index==ct_len) {
				break;
			}
		}
		if(first_quadrant_val!=0&&i!=0) {
			Point cur_org(300-i, 300-first_quadrant_val);
			if(getRandomNumber(0,10)>=6) {
				atari.push_back(cur_org);
				atari_set_q4+=captcha_text[ct_index];
			}
			putText(image, pattern?captcha_text.substr(ct_index, 1):captcha_text.substr(ct_index*3, 3), cur_org, FONT_HERSHEY_COMPLEX, getRandomNumber(1.5,2.5), Scalar(getRandomNumber(100, 255),getRandomNumber(100, 255),getRandomNumber(100, 255)), 2, 8);
			ct_index++;
			if(ct_index==ct_len) {
				break;
			}
		}
	}
	Point center(300, 300);
	for(Point const& i:atari) {
		float x_diff=i.x-center.x;
		float y_diff=i.y-center.y;
		Point val(center.x+x_diff*0.8, center.y+y_diff*0.8);
		arrowedLine(image, Point(300,300), val, Scalar(getRandomNumber(100, 255), getRandomNumber(100, 255), getRandomNumber(100, 255)), 6, 8);
	}
	//putText(image, "Start!", Point(90, 300), FONT_HERSHEY_COMPLEX, 2, Scalar(0,0,255), 2);
	int subpattern=0;
	if(pattern) {
		if(getRandomNumber(0,1)) {
			subpattern=1;
			arrowedLine(image, Point(20,270), Point(20,310), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(40,270), Point(40,310), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(60,270), Point(60,310), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(80,270), Point(80,310), Scalar(0, 0, 255), 6);
			ft2->putText(image, "请逆时针输入", Point(180, 250), 40, Scalar(0, 0, 255), 2, 8, true);
		}else{
			arrowedLine(image, Point(20,310), Point(20,270), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(40,310), Point(40,270), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(60,310), Point(60,270), Scalar(0, 0, 255), 6);
			arrowedLine(image, Point(80,310), Point(80,270), Scalar(0, 0, 255), 6);
			ft2->putText(image, "请顺时针输入", Point(180, 250), 40, Scalar(0, 0, 255), 2, 8, true);
		}
		ft2->putText(image, "从红色箭头开始", Point(180, 300), 40, Scalar(0, 0, 255), 2, 8, true);
		ft2->putText(image, "所有被中心箭头", Point(180, 350), 40, Scalar(0, 0, 255), 2, 8, true);
		ft2->putText(image, "指向的字母或数字", Point(180, 400), 40, Scalar(0, 0, 255), 2, 8, true);
	}else{
		ft2->putText(image, "请输入", Point(180, 250), 40, Scalar(0, 0, 255), 2, 8, true);
		ft2->putText(image, "所有被中心箭头", Point(180, 300), 40, Scalar(0, 0, 255), 2, 8, true);
		ft2->putText(image, "指向的数字之和", Point(180, 350), 40, Scalar(0, 0, 255), 2, 8, true);
		if(getRandomNumber(0,1)) {
			subpattern=1;
			ft2->putText(image, "的相反数", Point(180, 400), 40, Scalar(0,0,255),2,8,true);
		}
	}
	std::reverse(atari_set_q4.begin(), atari_set_q4.end());
	std::reverse(atari_set_q1.begin(), atari_set_q1.end());
	std::string atari_set=atari_set_q4+atari_set_q2+atari_set_q1+atari_set_q3;
	if(!pattern) {
		int final_result=0;
		for(int i=0;i<atari_set.length();i+=3) {
			final_result+=atari_set[i]-0x30;
		}
		if(subpattern) {
			output_text="-"+std::to_string(final_result);
			return 0;
		}
		output_text=std::to_string(final_result);
		return 0;
	}
	if(subpattern) {
		std::reverse(atari_set.begin(), atari_set.end());
	}
	output_text=atari_set;
	return 0;
#endif
  /*Size textsize = getTextSize(captcha_text, FONT_HERSHEY_COMPLEX, 2, 2, 0);
  Point org((IMAGE_W - textsize.width) / 2,
            ((IMAGE_H - textsize.height) / 2) + (textsize.height / 2));
	putText(image, "t", Point(50, 50), FONT_HERSHEY_COMPLEX, 2, Scalar(255, 200, getRandomNumber(155,200)), 2, 8);
	return 0;
  static const int lineType = 8;
  string text = captcha_text;
  Size textsize = getTextSize(text, FONT_HERSHEY_COMPLEX, 2, 2, 0);
  Point org((IMAGE_W - textsize.width) / 2,
            ((IMAGE_H - textsize.height) / 2) + (textsize.height / 2));
  Mat image2;
  for (int i = 0; i < 255; i += 2) {
    image2 = image - Scalar::all(0);
    putText(image2, text, org, FONT_HERSHEY_COMPLEX, 2,
            Scalar(0, 0, getRandomNumber(155, 200)), 2, lineType);
  }
  image2 = image - Scalar::all(50);
  putText(image2, captcha_text.substr(0, 1), org, FONT_HERSHEY_COMPLEX, 2, Scalar(255, 200, getRandomNumber(155,200)), 2, lineType);
  cv::Mat matE;
  cv::addWeighted(image2, 1.0, image, 1.0, 0.0, matE);
  matE.copyTo(image);
  return 0;*/
}

Scalar randomColor() {
  int icolor = (int)getRandomNumber(1, 65535);
  return Scalar(icolor & 255, (icolor >> 8) & 255, (icolor >> 16) & 255);
}
