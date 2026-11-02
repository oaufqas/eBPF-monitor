#include "app_context.h"

AppContext& AppContext::get() {
    static AppContext instance;
    return instance;
}