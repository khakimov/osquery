#include <string>
#include <iostream>
#include <fstream>

#include <osquery/osquery_worker.h>
#include <osquery/message.h>
#include <osquery/core.h>
#include <osquery/core/virtual_table.h>
#include <osquery/sql.h>
#include <osquery/database.h>

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

int main(int argc, char* argv[]) {
    // Get and cache our hostname, since we use it to identify ourselves
    dashiell::OsqueryWorker db;

    std::string test;
    test = db.runQuery("select * from users;");
    std::cout << test;
}
