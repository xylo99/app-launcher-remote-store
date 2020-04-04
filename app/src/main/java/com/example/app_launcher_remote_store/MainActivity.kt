package com.example.app_launcher_remote_store

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.RemoteException
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import de.blinkt.openvpn.LaunchVPN
import de.blinkt.openvpn.VpnProfile
import de.blinkt.openvpn.core.*
import org.json.JSONException
import org.json.JSONObject
import java.io.*
import java.nio.charset.Charset
import java.util.*

class MainActivity : AppCompatActivity(), VpnStatus.ByteCountListener, VpnStatus.StateListener {

    lateinit var mService: IOpenVPNServiceInternal

    lateinit var inputStream: InputStream
    lateinit var bufferedReader: BufferedReader
    lateinit var cp: ConfigParser
    lateinit var vp: VpnProfile
    lateinit var pm: ProfileManager
    lateinit var thread: Thread


    private fun startVpn(VPNFile: String) {
        try {
            try {
                assert(VPNFile != null)
                inputStream = ByteArrayInputStream(
                    VPNFile.toByteArray(
                        Charset.forName("UTF-8")
                    )
                )
            } catch (e: Exception) {
                    e.printStackTrace()
            }
            try { // M8
                assert(inputStream != null)
                bufferedReader =
                    BufferedReader(InputStreamReader(inputStream , Charset.forName("UTF-8")))
            } catch (e: Exception) {
                e.printStackTrace()
            }
            cp = ConfigParser()
            try {
                cp.parseConfig(bufferedReader)
            } catch (e: Exception) {
                e.printStackTrace()
            }
            vp = cp.convertProfile()
//            vp.mAllowedAppsVpnAreDisallowed = true
            val En = EncryptData()
            val AppValues = getSharedPreferences("app_values", 0)

            val randPW = UUID.randomUUID().toString().substring(0,15)

            val AppDetailsValues: String =
                En.decrypt(AppValues.getString("app_details", "NA"), randPW)
            try {
                val json_response = JSONObject(AppDetailsValues)
                val jsonArray = json_response.getJSONArray("blocked")
                for (i in 0 until jsonArray.length()) {
                    val json_object = jsonArray.getJSONObject(i)
                    vp.mAllowedAppsVpn.add(json_object.getString("app"))
                    Log.e("packages", json_object.getString("app"))

                }
            } catch (e: JSONException) {
                e.printStackTrace()
            }
            try {
                vp.mName = Build.MODEL
            } catch (e: Exception) {
                e.printStackTrace()

            }

            try {
                pm = ProfileManager.getInstance(this@MainActivity)
                pm.addProfile(vp)
                pm.saveProfileList(this@MainActivity)
                pm.saveProfile(this@MainActivity, vp)
                vp = pm.getProfileByName(Build.MODEL)
                val intent = Intent(applicationContext, LaunchVPN::class.java)
                intent.putExtra(LaunchVPN.EXTRA_KEY, vp.getUUID().toString())
                intent.action = Intent.ACTION_MAIN
                startActivity(intent)
                App.isStart = false
            } catch (e: Exception) {
                e.printStackTrace()

            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    fun stop_vpn() {
        App.connection_status = 0
        OpenVPNService.abortConnectionVPN = true
        ProfileManager.setConntectedVpnProfileDisconnected(this)
        if (mService != null) {
            try {
                mService.stopVPN(false)
            } catch (e: RemoteException) {
                val params = Bundle()
                params.putString("device_id", App.device_id)
                params.putString("exception", "MA18$e")
                //                mFirebaseAnalytics.logEvent("app_param_error", params);
            }
            try {
                pm = ProfileManager.getInstance(this)
                vp = pm.getProfileByName(Build.MODEL)
                pm.removeProfile(this, vp)
            } catch (e: Exception) {
                val params = Bundle()
                params.putString("device_id", App.device_id)
                params.putString("exception", "MA17$e")
                //mFirebaseAnalytics.logEvent("app_param_error", params);
            }
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            //startVpn(File)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun updateState(
        state: String?,
        logmessage: String?,
        localizedResId: Int,
        level: ConnectionStatus?
    ) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun setConnectedVPN(uuid: String?) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun updateByteCount(`in`: Long, out: Long, diffIn: Long, diffOut: Long) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }


}
