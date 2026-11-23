import Foundation

// The caller validates the trace payload and controls the deadline of this process.
final class Probe: NSObject, URLSessionDataDelegate {
    let finished = DispatchSemaphore(value:0)
    var data = Data()
    var succeeded = false

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session:URLSession, dataTask:URLSessionDataTask,
                    didReceive response:URLResponse, completionHandler:@escaping (URLSession.ResponseDisposition)->Void) {
        let ok=(response as? HTTPURLResponse)?.statusCode == 200 && response.expectedContentLength <= 65536
        completionHandler(ok ? .allow : .cancel)
    }
    func urlSession(_ session:URLSession, dataTask:URLSessionDataTask, didReceive bytes:Data) {
        if data.count + bytes.count > 65536 {dataTask.cancel();return}
        data.append(bytes)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        succeeded = error == nil && (task.response as? HTTPURLResponse)?.statusCode == 200 && !data.isEmpty
        finished.signal()
    }
}
let hosts=["claude.ai","api.anthropic.com","chatgpt.com","api.openai.com"]
guard CommandLine.arguments.count==2, let host=URL(string:CommandLine.arguments[1])?.host,
      hosts.contains(host), CommandLine.arguments[1]=="https://"+host+"/cdn-cgi/trace" else {exit(2)}
let cfg=URLSessionConfiguration.ephemeral
cfg.urlCache=nil
cfg.httpCookieStorage=nil
cfg.urlCredentialStorage=nil
cfg.timeoutIntervalForRequest=12
cfg.timeoutIntervalForResource=16
let probe=Probe()
let session=URLSession(configuration:cfg,delegate:probe,delegateQueue:nil)
var request=URLRequest(url:URL(string:CommandLine.arguments[1]+"?_="+UUID().uuidString)!)
request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
request.setValue("no-store",forHTTPHeaderField:"Cache-Control")
session.dataTask(with:request).resume()
guard probe.finished.wait(timeout:.now()+17) == .success, probe.succeeded else {exit(1)}
FileHandle.standardOutput.write(probe.data)
