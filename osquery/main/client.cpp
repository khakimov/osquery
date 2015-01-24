#include <string>
#include <iostream>
#include <fstream>

#include <osquery/osquery_worker.h>
#include <osquery/message.h>
#include <osquery/core.h>
#include <osquery/core/virtual_table.h>
#include <osquery/sql.h>
#include <osquery/database.h>
#include <curl/curl.h>

namespace dashiell{
    bool OsqueryWorker::isInit = false;

    OsqueryWorker::OsqueryWorker(){
        // Only load in our osquery info once!
        if(!isInit){
            char* argv[] = {};
            osquery::initOsquery(0,argv);
            isInit = true;
        }
    }

    std::string OsqueryWorker::runQuery(std::string query) {
        // Get our QueryData from osQuery
        auto sql = osquery::SQL(query);
        if(sql.ok()) {
            // Serialize the rows to JSON and return
            boost::property_tree::ptree results_payload;
            int i = 0;
            for (const auto& r : sql.rows()) {
                i++;
                boost::property_tree::ptree serialized;
                auto s = osquery::serializeRow(r, serialized);
                results_payload.push_back(std::make_pair(std::to_string(i), serialized));
            }
            std::ostringstream os;
            boost::property_tree::write_json(os, results_payload, false);

            return os.str();
        }

        return "";
    }

    std::string OsqueryWorker::getHostname() {
        return osquery::getHostname();
    }
}

std::string hostname;


std::string data; //will hold the urls contents

size_t writeCallback(char* buf, size_t size, size_t nmemb, void* up)
{ //callback must have this declaration
    //buf is a pointer to the data that curl has for us
    //size*nmemb is the size of the buffer

    for (int c = 0; c<size*nmemb; c++)
    {
        data.push_back(buf[c]);
    }
    return size*nmemb; //tell curl how many bytes we handled
}

int main(int argc, char* argv[]) {
    // Get and cache our hostname, since we use it to identify ourselves
    dashiell::OsqueryWorker db;

    std::string test;
    test = db.runQuery("select * from users;");
    std::cout << test;

    curl_global_init( CURL_GLOBAL_ALL );
    CURL * myHandle;
    CURLcode result; // We’ll store the result of CURL’s webpage retrieval, for simple error checking.
    myHandle = curl_easy_init ( ) ;
    // Notice the lack of major error checking, for brevity
    curl_easy_setopt(myHandle, CURLOPT_URL, "http://127.0.0.1:8080/report");
    // char *data="username=your_username_here&password=test";
    curl_easy_setopt(myHandle, CURLOPT_POSTFIELDS, test.c_str());
    curl_easy_perform( myHandle );

    curl_easy_cleanup( myHandle ); 

    return 0;
}
