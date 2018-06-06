/* Copyright 2018 Ionic Security Inc. All Rights Reserved.
 * Unauthorized use, reproduction, redistribution, modification, or disclosure is strictly prohibited.
 */

#include <string>
#include <iostream>
#include <stdlib.h>
#include <algorithm>


namespace {
bool checkAnswerOK(std::string& answer, bool& result)
{
    std::transform(answer.begin(), answer.end(), answer.begin(),
                   [](unsigned char x){return ::tolower(x);});

     bool answer_valid =
            (answer == "y")   ||
            (answer == "n")   ||
            (answer == "yes") ||
            (answer == "no");

    result = answer_valid && answer[0] == 'y';
    return answer_valid;
}
}

bool question_yesno(std::string const& message)
{
    std::string answer;
    bool        result;

    std::cout << message << "? [Y/n]\n";
    while(std::cin >> answer && !checkAnswerOK(answer, result))
    {
        std::cout << "Invalid answer: " << answer << " Please try again\n"
                  << message << "? [Y/n]\n";
    }
    if (!std::cin) {
        return false;
    }
    return result;
}
