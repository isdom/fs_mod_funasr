#include <switch.h>
#include <fstream>
#include <math.h>

#define ASIO_STANDALONE 1

#include <websocketpp/client.hpp>
#include <websocketpp/common/thread.hpp>
#include <websocketpp/config/asio_client.hpp>
#include <thread>

#include "nlohmann/json.hpp"

bool g_debug = false;

typedef struct {
    switch_atomic_t fun_asr_concurrent_cnt;
} fun_asr_global_t;

fun_asr_global_t *fun_asr_globals;

template<typename T>
class WebsocketClient;

typedef WebsocketClient<websocketpp::config::asio_tls_client> funasr_client;

// public declare

typedef void (*on_asr_started_func_t) (void *);
typedef void (*on_asr_sentence_begin_func_t) (void *);
typedef void (*on_asr_sentence_end_func_t) (void *, const char *sentence);
typedef void (*on_asr_result_changed_func_t) (void *, const char *result);
typedef void (*on_asr_stopped_func_t) (void *);

typedef struct {
    void *asr_caller;
    on_asr_started_func_t on_asr_started_func;
    on_asr_sentence_begin_func_t on_asr_sentence_begin_func;
    on_asr_sentence_end_func_t on_asr_sentence_end_func;
    on_asr_result_changed_func_t on_asr_result_changed_func;
    on_asr_stopped_func_t on_asr_stopped_func;
} asr_callback_t;

typedef void *(*asr_init_func_t) (switch_core_session_t *, const switch_codec_implementation_t *, const char *);
typedef bool (*asr_start_func_t) (void *asr_data, asr_callback_t *asr_callback);
typedef bool (*asr_send_audio_func_t) (void *asr_data, void *data, uint32_t data_len);
typedef void (*asr_stop_func_t) (void *asr_data);
typedef void (*asr_destroy_func_t) (void *asr_data);

typedef struct {
    asr_init_func_t asr_init_func;
    asr_start_func_t asr_start_func;
    asr_send_audio_func_t asr_send_audio_func;
    asr_stop_func_t asr_stop_func;
    asr_destroy_func_t asr_destroy_func;
} asr_provider_t;

// public declare end

//======================================== fun asr start ===============

typedef struct {
    switch_core_session_t *session;
    funasr_client *fac;
    int started;
    int stopped;
    int starting;
    switch_mutex_t *mutex;
    switch_audio_resampler_t *re_sampler;
    char *fun_url;
    char *asr_dec_vol;
    float vol_multiplier;
    asr_callback_t *asr_callback;
} fun_asr_context_t;

/**
 * 识别启动回调函数
 *
 * @param pvt
 */
void onAsrTranscriptionStarted(fun_asr_context_t *pvt) {
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "onAsrTranscriptionStarted: funasr\n");
    }
    switch_mutex_lock(pvt->mutex);
    pvt->started = 1;
    pvt->starting = 0;
    switch_mutex_unlock(pvt->mutex);

    if (pvt->asr_callback) {
        pvt->asr_callback->on_asr_started_func(pvt->asr_callback->asr_caller);
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "onAsrTranscriptionStarted: pvt->asr_callback is null\n");
    }
}

/**
 * @brief 一句话开始回调函数
 *
 * @param pvt
 */
void onAsrSentenceBegin(fun_asr_context_t *pvt) {
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "onAsrSentenceBegin: funasr\n");
    }
//    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,"onAsrSentenceBegin: status code=%d, task id=%s, index=%d, time=%d\n", cbEvent->getStatusCode(), cbEvent->getTaskId(),
//                    cbEvent->getSentenceIndex(),
//                    cbEvent->getSentenceTime());
}

/**
 * @brief 一句话结束回调函数
 *
 * @param pvt
 * @param text
 */
void onAsrSentenceEnd(fun_asr_context_t *pvt, const std::string &text) {
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "onAsrSentenceEnd: funasr\n");
    }
    if (pvt->asr_callback) {
        pvt->asr_callback->on_asr_sentence_end_func(pvt->asr_callback->asr_caller, text.c_str());
    }
}

/**
 * @brief 识别结果变化回调函数
 *
 * @param pvt
 * @param text
 */
void onAsrTranscriptionResultChanged(fun_asr_context_t *pvt, const std::string &text) {
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "onAsrTranscriptionResultChanged: funasr\n");
    }
    if (pvt->asr_callback) {
        pvt->asr_callback->on_asr_result_changed_func(pvt->asr_callback->asr_caller, text.c_str());
    }
}

/**
 * @brief 语音转写结束回调函数
 *
 * @param pvt
 */
void onAsrTranscriptionCompleted(fun_asr_context_t *pvt) {
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "onAsrTranscriptionCompleted: funasr\n");
    }
}

/**
 * @brief 异常识别回调函数
 *
 * @param pvt
 */
void onAsrTaskFailed(fun_asr_context_t *pvt) {
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "onAsrTaskFailed: funasr\n");
    }
    switch_mutex_lock(pvt->mutex);
    pvt->started = 0;
    switch_mutex_unlock(pvt->mutex);
}

/**
 * @brief 识别通道关闭回调函数
 *
 * @param pvt
 */
void onAsrChannelClosed(fun_asr_context_t *pvt) {
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "onAsrChannelClosed: funasr\n");
    }
    if (pvt->asr_callback) {
        pvt->asr_callback->on_asr_stopped_func(pvt->asr_callback->asr_caller);
    }
}

/**
 * Define a semi-cross platform helper method that waits/sleeps for a bit.
 */
void WaitABit() {
#ifdef WIN32
    Sleep(1000);
#else
    usleep(1000);
#endif
}

typedef websocketpp::config::asio_client::message_type::ptr message_ptr;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

context_ptr OnTlsInit(const websocketpp::connection_hdl &) {
    context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

    try {
        ctx->set_options(
                asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                asio::ssl::context::no_sslv3 | asio::ssl::context::single_dh_use);

    } catch (std::exception &e) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
                          "OnTlsInit asio::ssl::context::set_options exception: %s\n", e.what());
    }
    return ctx;
}

// template for tls or not config
template<typename T>
class WebsocketClient {
public:
    // typedef websocketpp::client<T> client;
    // typedef websocketpp::client<websocketpp::config::asio_tls_client>
    // wss_client;
    typedef websocketpp::lib::lock_guard<websocketpp::lib::mutex> scoped_lock;

    WebsocketClient(int is_ssl, fun_asr_context_t *asr_context) : m_open(false), m_done(false) {
        m_asr_ctx = asr_context;

        // set up access channels to only log interesting things
        m_client.clear_access_channels(websocketpp::log::alevel::all);
        m_client.set_access_channels(websocketpp::log::alevel::connect);
        m_client.set_access_channels(websocketpp::log::alevel::disconnect);
        m_client.set_access_channels(websocketpp::log::alevel::app);

        // Initialize the Asio transport policy
        m_client.init_asio();
        m_client.start_perpetual();

        // Bind the handlers we are using
        using websocketpp::lib::bind;
        using websocketpp::lib::placeholders::_1;
        m_client.set_open_handler(bind(&WebsocketClient::on_open, this, _1));
        m_client.set_close_handler(bind(&WebsocketClient::on_close, this, _1));

        m_client.set_message_handler(
                [this](websocketpp::connection_hdl hdl, message_ptr msg) {
                    on_message(hdl, msg);
                });

        m_client.set_fail_handler(bind(&WebsocketClient::on_fail, this, _1));
        m_client.clear_access_channels(websocketpp::log::alevel::all);
    }

    std::string getThreadIdOfString(const std::thread::id &id) {
        std::stringstream sin;
        sin << id;
        return sin.str();
    }

    void on_message(websocketpp::connection_hdl hdl, message_ptr msg) {
        const std::string &payload = msg->get_payload();
        switch (msg->get_opcode()) {
            case websocketpp::frame::opcode::text: {
                nlohmann::json asrresult = nlohmann::json::parse(payload);
                std::string id_str = getThreadIdOfString(std::this_thread::get_id());
                if (g_debug) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "thread: %s, on_message = %s\n",
                                      id_str.c_str(),
                                      payload.c_str());
                }

                if (asrresult["mode"] == "2pass-online") {
                    onAsrTranscriptionResultChanged(m_asr_ctx, asrresult["text"]);
                } else if (asrresult["mode"] == "2pass-offline") {
                    onAsrSentenceEnd(m_asr_ctx, asrresult["text"]);
                }

                if (asrresult["is_final"] == true) {
                    websocketpp::lib::error_code ec;

                    m_client.close(hdl, websocketpp::close::status::going_away, "", ec);

                    if (ec) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Error closing connection: %s\n",
                                          ec.message().c_str());
                    }
                }
            }
                break;
            default:
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "un-handle opcode: %d\n", msg->get_opcode());
                break;
        }
    }

    // This method will block until the connection is complete
    int start(const std::string &uri, const std::string &asr_mode, std::vector<int> chunk_vector) {
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "start wsc with: %s mode: %s\n", uri.c_str(),
                              asr_mode.c_str());
        }

        {
            // Create a new connection to the given URI
            websocketpp::lib::error_code ec;
            typename websocketpp::client<T>::connection_ptr con = m_client.get_connection(uri, ec);
            if (ec) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Get Connection Error: %s\n",
                                  ec.message().c_str());
                return -1;
            }
            // Grab a handle for this connection so we can talk to it in a thread
            // safe manor after the event loop starts.
            m_hdl = con->get_handle();

            // Queue the connection. No DNS queries or network connections will be
            // made until the io_service event loop is run.
            m_client.connect(con);
        }

        // Create a thread to run the ASIO io_service event loop
        m_thread.reset(new websocketpp::lib::thread(&websocketpp::client<T>::run, &m_client));

        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "start send wsc first msg\n");
        }
        // first message
        bool wait = false;
        while (true) {
            {
                scoped_lock guard(m_lock);
                // If the connection has been closed, stop generating data
                if (m_done) {
//              break;
                    return -1;
                }
                // If the connection hasn't been opened yet wait a bit and retry
                if (!m_open) {
                    wait = true;
                } else {
                    break;
                }
            }

            if (wait) {
                // LOG(INFO) << "wait.." << m_open;
                WaitABit();
                continue;
            }
        }

        {
            nlohmann::json jsonbegin;
            nlohmann::json chunk_size = nlohmann::json::array();
            chunk_size.push_back(chunk_vector[0]);
            chunk_size.push_back(chunk_vector[1]);
            chunk_size.push_back(chunk_vector[2]);
            jsonbegin["mode"] = asr_mode;
            jsonbegin["chunk_size"] = chunk_size;
            jsonbegin["wav_name"] = "asr";
            jsonbegin["wav_format"] = "pcm";
            jsonbegin["is_speaking"] = true;

            websocketpp::lib::error_code ec;
            m_client.send(m_hdl, jsonbegin.dump(), websocketpp::frame::opcode::text, ec);
            if (ec) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "funasr send begin msg failed: %s\n",
                                  ec.message().c_str());
            } else {
                if (g_debug) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "funasr send begin msg success\n");
                }
            }
        }

        return 0;
    }

    void stop() {
        {
            nlohmann::json jsonend;
            jsonend["is_speaking"] = false;
            websocketpp::lib::error_code ec;
            m_client.send(m_hdl, jsonend.dump(), websocketpp::frame::opcode::text, ec);
            if (ec) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "funasr send end msg failed: %s\n",
                                  ec.message().c_str());
            } else {
                if (g_debug) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "funasr send end msg success\n");
                }
            }
        }

        m_client.stop_perpetual();
        m_thread->join();

        onAsrChannelClosed(m_asr_ctx);
    }

    // The open handler will signal that we are ready to start sending data
    void on_open(const websocketpp::connection_hdl &) {
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Connection opened, starting data!\n");
        }

        {
            scoped_lock guard(m_lock);
            m_open = true;
        }
        onAsrTranscriptionStarted(m_asr_ctx);
    }

    // The close handler will signal that we should stop sending data
    void on_close(const websocketpp::connection_hdl &) {
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Connection closed, stopping data!\n");
        }

        {
            scoped_lock guard(m_lock);
            m_done = true;
        }
        onAsrTranscriptionCompleted(m_asr_ctx);
    }

    // The fail handler will signal that we should stop sending data
    void on_fail(const websocketpp::connection_hdl &) {
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Connection failed, stopping data!\n");
        }

        {
            scoped_lock guard(m_lock);
            m_done = true;
        }
        onAsrTaskFailed(m_asr_ctx);
    }

    void sendAudio(uint8_t *dp, size_t data_len, websocketpp::lib::error_code &ec) {
        m_client.send(m_hdl, dp, data_len, websocketpp::frame::opcode::binary, ec);
    }

    websocketpp::client<T> m_client;
    websocketpp::lib::shared_ptr<websocketpp::lib::thread> m_thread;

private:

    fun_asr_context_t *m_asr_ctx;
    websocketpp::connection_hdl m_hdl;
    websocketpp::lib::mutex m_lock;
    bool m_open;
    bool m_done;
};

// typedef WebsocketClient<websocketpp::config::asio_tls_client> funasr_client;

#define MAX_FRAME_BUFFER_SIZE (1024*1024) //1MB
#define SAMPLE_RATE 16000

funasr_client *generateAsrClient(fun_asr_context_t *pvt) {
    auto *fac = new funasr_client(1, pvt);
    if (!fac) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "generateAsrClient failed.\n");
        return nullptr;
    }

    fac->m_client.set_tls_init_handler(bind(&OnTlsInit, ::_1));

    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "funasr url is:%s, vol multiplier is:%f\n",
                          pvt->fun_url, pvt->vol_multiplier);
    }
    return fac;
}

//======================================== fun asr end ===============

//======================================== freeswitch module start ===============
SWITCH_MODULE_LOAD_FUNCTION(mod_funasr_load);

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_funasr_shutdown);

extern "C"
{
SWITCH_MODULE_DEFINITION(mod_funasr, mod_funasr_load, mod_funasr_shutdown, nullptr);
};

static void *init_fun_asr(switch_core_session_t *session, const switch_codec_implementation_t *read_impl, const char *cmd);

static bool start_fun_asr(fun_asr_context_t *pvt, asr_callback_t *asr_callback);

static bool send_audio_to_fun_asr(fun_asr_context_t *pvt, void *data, uint32_t data_len);

static void stop_fun_asr(fun_asr_context_t *pvt);

static void destroy_fun_asr(fun_asr_context_t *pvt);

static const asr_provider_t fun_asr_funcs = {
        init_fun_asr,
        reinterpret_cast<asr_start_func_t>(start_fun_asr),
        reinterpret_cast<asr_send_audio_func_t>(send_audio_to_fun_asr),
        reinterpret_cast<asr_stop_func_t>(stop_fun_asr),
        reinterpret_cast<asr_destroy_func_t>(destroy_fun_asr)
};

static switch_status_t attach_fun_asr_provider_on_channel_init(switch_core_session_t *session) {
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_channel_set_private(channel, "fun_asr", &fun_asr_funcs);
    return SWITCH_STATUS_SUCCESS;
}

switch_state_handler_table_t fun_asr_cs_handlers = {
        /*! executed when the state changes to init */
        // switch_state_handler_t on_init;
        attach_fun_asr_provider_on_channel_init,
        /*! executed when the state changes to routing */
        // switch_state_handler_t on_routing;
        nullptr,
        /*! executed when the state changes to execute */
        // switch_state_handler_t on_execute;
        nullptr,
        /*! executed when the state changes to hangup */
        // switch_state_handler_t on_hangup;
        nullptr,
        /*! executed when the state changes to exchange_media */
        // switch_state_handler_t on_exchange_media;
        nullptr,
        /*! executed when the state changes to soft_execute */
        // switch_state_handler_t on_soft_execute;
        nullptr,
        /*! executed when the state changes to consume_media */
        // switch_state_handler_t on_consume_media;
        nullptr,
        /*! executed when the state changes to hibernate */
        // switch_state_handler_t on_hibernate;
        nullptr,
        /*! executed when the state changes to reset */
        // switch_state_handler_t on_reset;
        nullptr,
        /*! executed when the state changes to park */
        // switch_state_handler_t on_park;
        nullptr,
        /*! executed when the state changes to reporting */
        // switch_state_handler_t on_reporting;
        nullptr,
        /*! executed when the state changes to destroy */
        // switch_state_handler_t on_destroy;
        nullptr,
        // int flags;
        0
};

void adjustVolume(int16_t *pcm, size_t pcm_len, float vol_multiplier) {
    int32_t pcm_val;
    for (size_t ctr = 0; ctr < pcm_len; ctr++) {
        pcm_val = (int32_t)pcm[ctr] * vol_multiplier;
        if (pcm_val < 32767 && pcm_val > -32768) {
            pcm[ctr] = (int16_t)pcm_val;
        } else if (pcm_val > 32767) {
            pcm[ctr] = 32767;
        } else if (pcm_val < -32768) {
            pcm[ctr] = -32768;
        }
    }
}

// uuid_start_funasr <uuid> funurl=<uri>
#define MAX_API_ARGC 10

static void *init_fun_asr(switch_core_session_t *session, const switch_codec_implementation_t *read_impl, const char *cmd) {
    char *_fun_url = nullptr;
    char *_asr_dec_vol = nullptr;

    switch_memory_pool_t *pool;
    switch_core_new_memory_pool(&pool);
    char *my_cmd = switch_core_strdup(pool, cmd);

    char *argv[MAX_API_ARGC];
    memset(argv, 0, sizeof(char *) * MAX_API_ARGC);

    int argc = switch_split(my_cmd, ' ', argv);
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "cmd:%s, args count: %d\n", my_cmd, argc);
    }

    for (int idx = 1; idx < MAX_API_ARGC; idx++) {
        if (argv[idx]) {
            char *ss[2] = {nullptr, nullptr};
            int cnt = switch_split(argv[idx], '=', ss);
            if (cnt == 2) {
                char *var = ss[0];
                char *val = ss[1];
                if (g_debug) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "process arg: %s = %s\n", var, val);
                }
                if (!strcasecmp(var, "funurl")) {
                    _fun_url = val;
                    continue;
                }
                if (!strcasecmp(var, "asr_dec_vol")) {
                    _asr_dec_vol = val;
                    continue;
                }
            }
        }
    }

    if (!_fun_url) {
        switch_core_destroy_memory_pool(&pool);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "funurl is required.\n");
        return nullptr;
    }

    fun_asr_context_t *pvt;
    if (!(pvt = (fun_asr_context_t *) switch_core_session_alloc(session, sizeof(fun_asr_context_t)))) {
        goto end;
    }
    pvt->started = 0;
    pvt->stopped = 0;
    pvt->starting = 0;
    pvt->session = session;
    pvt->fun_url = switch_core_session_strdup(session, _fun_url);
    pvt->asr_dec_vol = _asr_dec_vol ? switch_core_session_strdup(session, _asr_dec_vol) : nullptr;
    if (pvt->asr_dec_vol) {
        double db = strtod(pvt->asr_dec_vol, nullptr);
        pvt->vol_multiplier = (float)pow(10, db / 20);
    }
    switch_mutex_init(&pvt->mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));

    if (read_impl->actual_samples_per_second != SAMPLE_RATE) {
        if (switch_resample_create(&pvt->re_sampler,
                                   read_impl->actual_samples_per_second,
                                   SAMPLE_RATE,
                                   16 * (read_impl->microseconds_per_packet / 1000) * 2,
                                   SWITCH_RESAMPLE_QUALITY,
                                   1) != SWITCH_STATUS_SUCCESS) {
            // release all resource alloc before
            switch_mutex_destroy(pvt->mutex);

            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to allocate re_sampler\n");
            pvt = nullptr;
            goto end;
        }
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT,
                              "create re-sampler bcs of media sampler/s is %d but fun asr support: %d, while ms/p: %d\n",
                              read_impl->actual_samples_per_second, SAMPLE_RATE, read_impl->microseconds_per_packet);
        }
    }

    // increment funasr concurrent count
    switch_atomic_inc(&fun_asr_globals->fun_asr_concurrent_cnt);

end:
    switch_core_destroy_memory_pool(&pool);
    return pvt;
}

static bool start_fun_asr(fun_asr_context_t *pvt, asr_callback_t *asr_callback) {
    bool  ret_val = false;
    if (pvt->stopped == 1) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "start_fun_asr: pvt->stopped\n");
        return ret_val;
    }

    switch_mutex_lock(pvt->mutex);
    if (pvt->started == 0) {
        if (pvt->starting == 0) {
            pvt->starting = 1;
            if (g_debug) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Starting Transaction \n");
            }
            switch_channel_t *channel = switch_core_session_get_channel(pvt->session);
            pvt->asr_callback = asr_callback;
            funasr_client *fac = generateAsrClient(pvt);
            if (!fac) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Asr Client init failed.%s\n",
                                  switch_channel_get_name(channel));
                ret_val = false;
                goto unlock;
            }
            pvt->fac = fac;
            if (g_debug) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Init Fun Asr Client.%s\n",
                                  switch_channel_get_name(channel));
            }

            std::vector<int> chunk_size;
            chunk_size.push_back(5);
            chunk_size.push_back(10);
            chunk_size.push_back(5);

            if (pvt->fac->start(std::string(pvt->fun_url), "2pass", chunk_size) < 0) {
                pvt->stopped = 1;
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE,
                                  "start() failed. may be can not connect server. please check network or firewalld:%s\n",
                                  switch_channel_get_name(channel));
                pvt->fac->stop();
                delete pvt->fac;
                pvt->fac = nullptr;
                // start()失败，释放request对象
                ret_val = false;
                goto unlock;
            }
            ret_val = true;
        }
    }

    unlock:
    switch_mutex_unlock(pvt->mutex);
    return ret_val;
}

static bool send_audio_to_fun_asr(fun_asr_context_t *pvt, void *data, uint32_t data_len) {
    bool  ret_val = false;
    // send audio to asr
    switch_mutex_lock(pvt->mutex);

    if (pvt->fac) {
        if (pvt->re_sampler) {
            //====== resample ==== ///
            switch_resample_process(pvt->re_sampler, (int16_t *) data, (int) data_len / 2 / 1);
            memcpy(data, pvt->re_sampler->to, pvt->re_sampler->to_len * 2 * 1);
            data_len = pvt->re_sampler->to_len * 2 * 1;
            if (g_debug) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "ASR new samples:%d\n",
                                  pvt->re_sampler->to_len);
            }
        }
        if (pvt->asr_dec_vol) {
            adjustVolume((int16_t *) data, (size_t) data_len / 2, pvt->vol_multiplier);
        }

        if (pvt->started) {
            websocketpp::lib::error_code ec;
            pvt->fac->sendAudio((uint8_t *) data, (size_t) data_len, ec);

            if (ec) {
                pvt->stopped = 1;
                switch_channel_t *channel = switch_core_session_get_channel(pvt->session);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "send audio failed: %s -> on channel: %s\n",
                                  ec.message().c_str(), switch_channel_get_name(channel));
                pvt->fac->stop();
                delete pvt->fac;
                pvt->fac = nullptr;
                ret_val = false;
                goto unlock;
            }
        } else {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "send_audio_to_fun_asr: funasr starting, ignore send audio\n");
        }
        ret_val = true;
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "send_audio_to_fun_asr: send audio %d\n",
                              data_len);
        }
    } else {
        switch_channel_t *channel = switch_core_session_get_channel(pvt->session);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "try send audio but fac has been released -> on channel: %s\n",
                          switch_channel_get_name(channel));
        ret_val = false;
    }

    unlock:
    switch_mutex_unlock(pvt->mutex);
    return ret_val;
}

static void stop_fun_asr(fun_asr_context_t *pvt) {
    switch_mutex_lock(pvt->mutex);
    switch_channel_t *channel = switch_core_session_get_channel(pvt->session);
    if (pvt->fac) {
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "try to stop fun asr on channel: %s\n",
                              switch_channel_get_name(channel));
        }
        pvt->fac->stop();
        //7: 识别结束, 释放fac对象
        delete pvt->fac;
        pvt->fac = nullptr;
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "stop fun asr and fac is released on channel: %s\n",
                              switch_channel_get_name(channel));
        }
    } else {
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING,
                              "fun asr has already stopped and released on channel:%s\n",
                              switch_channel_get_name(channel));
        }
    }
    switch_mutex_unlock(pvt->mutex);
}

static void destroy_fun_asr(fun_asr_context_t *pvt) {
    switch_core_session_t *session = pvt->session;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(pvt->session), SWITCH_LOG_NOTICE,
                          "destroy_fun_asr: release all resource for session -> on channel: %s\n",
                          switch_channel_get_name(channel));
    }
    stop_fun_asr(pvt);
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE,
                          "destroy_fun_asr: stop_fun_asr -> channel: %s\n",
                          switch_channel_get_name(channel));
    }

    // decrement funasr concurrent count
    switch_atomic_dec(&fun_asr_globals->fun_asr_concurrent_cnt);

    if (pvt->re_sampler) {
        switch_resample_destroy(&pvt->re_sampler);
        if (g_debug) {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE,
                              "destroy_fun_asr: switch_resample_destroy -> on channel: %s\n",
                              switch_channel_get_name(channel));
        }
    }
    switch_mutex_destroy(pvt->mutex);
    if (g_debug) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE,
                          "destroy_fun_asr: switch_mutex_destroy -> on channel: %s\n",
                          switch_channel_get_name(channel));
    }
}

SWITCH_STANDARD_API(funasr_concurrent_cnt_function) {
    const uint32_t concurrent_cnt = switch_atomic_read (&fun_asr_globals->fun_asr_concurrent_cnt);
    stream->write_function(stream, "%d\n", concurrent_cnt);
    switch_event_t *event = nullptr;
    if (switch_event_create(&event, SWITCH_EVENT_CUSTOM) == SWITCH_STATUS_SUCCESS) {
        event->subclass_name = strdup("funasr_concurrent_cnt");
        switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "Event-Subclass", event->subclass_name);
        switch_event_add_header(event, SWITCH_STACK_BOTTOM, "Funasr-Concurrent-Cnt", "%d", concurrent_cnt);
        switch_event_fire(&event);
    }

    return SWITCH_STATUS_SUCCESS;
}

#define FUN_ASR_DEBUG_SYNTAX "<on|off>"
SWITCH_STANDARD_API(mod_funasr_debug)
{
    if (zstr(cmd)) {
        stream->write_function(stream, "-USAGE: %s\n", FUN_ASR_DEBUG_SYNTAX);
    } else {
        if (!strcasecmp(cmd, "on")) {
            g_debug = true;
            stream->write_function(stream, "funasr Debug: on\n");
        } else if (!strcasecmp(cmd, "off")) {
            g_debug = false;
            stream->write_function(stream, "funasr Debug: off\n");
        } else {
            stream->write_function(stream, "-USAGE: %s\n", FUN_ASR_DEBUG_SYNTAX);
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

/**
 *  定义load函数，加载时运行
 */
SWITCH_MODULE_LOAD_FUNCTION(mod_funasr_load) {
    switch_api_interface_t *api_interface = nullptr;
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "mod_funasr load starting\n");

    fun_asr_globals = (fun_asr_global_t *)switch_core_alloc(pool, sizeof(fun_asr_global_t));

    // register global state handlers
    switch_core_add_state_handler(&fun_asr_cs_handlers);

    SWITCH_ADD_API(api_interface,
                   "funasr_concurrent_cnt",
                   "funasr_concurrent_cnt api",
                   funasr_concurrent_cnt_function,
                   "<cmd><args>");

    SWITCH_ADD_API(api_interface, "funasr_debug", "Set funasr debug", mod_funasr_debug, FUN_ASR_DEBUG_SYNTAX);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "mod_funasr loaded\n");

    return SWITCH_STATUS_SUCCESS;
}

/**
 *  定义shutdown函数，关闭时运行
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_funasr_shutdown) {
    // unregister global state handlers
    switch_core_remove_state_handler(&fun_asr_cs_handlers);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, " mod_funasr shutdown called\n");
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, " mod_funasr unload\n");
    return SWITCH_STATUS_SUCCESS;
}