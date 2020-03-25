package com.example.app_launcher_remote_store

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import de.blinkt.openvpn.VpnProfile
import de.blinkt.openvpn.core.ConfigParser
import de.blinkt.openvpn.core.ConnectionStatus
//import de.blinkt.openvpn.core.IOpenVPNServiceInternal
import de.blinkt.openvpn.core.ProfileManager
import de.blinkt.openvpn.core.VpnStatus
import java.io.BufferedReader
import java.io.InputStream

class MainActivity : AppCompatActivity(), VpnStatus.ByteCountListener, VpnStatus.StateListener {

    //var mService: IOpenVPNServiceInternal? = null

    var inputStream: InputStream? = null
    var bufferedReader: BufferedReader? = null
    var cp: ConfigParser? = null
    var vp: VpnProfile? = null
    var pm: ProfileManager? = null
    var thread: Thread? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

    
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
