#include <nan.h>
#include <v8.h>
#include <string>

using namespace v8;

// Given a function, return an object with the following properties:
// - startLine: the line number of the function definition
// - startColumn: the column number of the function definition
// - filePath: the file where the function is defined
NAN_METHOD(GetFunctionLocation)
{
    if (info.Length() < 1 || !info[0]->IsFunction())
    {
        Nan::ThrowTypeError("Expected a function as the first argument.");
        return;
    }

    Local<Function> jsFunction = info[0].As<Function>();

    // https://v8docs.nodesource.com/node-0.12/d5/d54/classv8_1_1_function.html#af91c39028b0899f307010477192cedd5
    // 1-based line numbers and 0-based column numbers
    int lineNumber = jsFunction->GetScriptLineNumber() + 1;
    int columnNumber = jsFunction->GetScriptColumnNumber();

    Local<Object> result = Nan::New<Object>();
    result->Set(Nan::GetCurrentContext(),
                Nan::New("startLine").ToLocalChecked(),
                Nan::New(lineNumber));
    result->Set(Nan::GetCurrentContext(),
                Nan::New("startColumn").ToLocalChecked(),
                Nan::New(columnNumber));

    Nan::Utf8String fileName(jsFunction->GetScriptOrigin().ResourceName());
    std::string fileNameStr(*fileName);
    if (fileNameStr.find("file://") == 0)
    {
        fileNameStr = fileNameStr.substr(7);
    }

    result->Set(Nan::GetCurrentContext(),
                Nan::New("filePath").ToLocalChecked(),
                Nan::New(fileNameStr).ToLocalChecked());

    info.GetReturnValue().Set(result);
}

NAN_MODULE_INIT(Init)
{
    Nan::Set(target, Nan::New("getFunctionLocation").ToLocalChecked(),
             Nan::GetFunction(Nan::New<FunctionTemplate>(GetFunctionLocation)).ToLocalChecked());
}

NODE_MODULE(function_location, Init)
