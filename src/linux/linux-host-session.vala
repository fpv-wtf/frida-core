namespace Frida {
	public class LinuxHostSessionBackend : Object, HostSessionBackend {
		private LinuxHostSessionProvider local_provider;

		public async void start (Cancellable? cancellable) throws IOError {
			assert (local_provider == null);
			local_provider = new LinuxHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close (cancellable);
			local_provider = null;
		}
	}

	public class LinuxHostSessionProvider : Object, HostSessionProvider {
		public string id {
			get { return "local"; }
		}

		public string name {
			get { return "Local System"; }
		}

		public Variant? icon {
			get { return null; }
		}

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL; }
		}

		private LinuxHostSession host_session;

		public async void close (Cancellable? cancellable) throws IOError {
			if (host_session == null)
				return;
			host_session.agent_session_detached.disconnect (on_agent_session_detached);
			yield host_session.close (cancellable);
			host_session = null;
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			var tempdir = new TemporaryDirectory ();

			host_session = new LinuxHostSession (new LinuxHelperProcess (tempdir), tempdir);
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			host_session.agent_session_detached.disconnect (on_agent_session_detached);

			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return yield this.host_session.link_agent_session (id, sink, cancellable);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}
	}

	public class LinuxHostSession : BaseDBusHostSession {
		public LinuxHelper helper {
			get;
			construct;
		}

		public TemporaryDirectory tempdir {
			get;
			construct;
		}

		public bool report_crashes {
			get;
			construct;
		}

		private AgentContainer system_session_container;

		private AgentDescriptor? agent;

		private ApplicationEnumerator application_enumerator = new ApplicationEnumerator ();
		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		public LinuxHostSession (owned LinuxHelper helper, owned TemporaryDirectory tempdir, bool report_crashes = true) {
			Object (
				helper: helper,
				tempdir: tempdir,
				report_crashes: report_crashes
			);
		}

		construct {
			helper.output.connect (on_output);

			injector = new Linjector (helper, false, tempdir);
			injector.uninjected.connect (on_uninjected);

#if HAVE_EMBEDDED_ASSETS
			var blob32 = Frida.Data.Agent.get_frida_agent_32_so_blob ();
			var blob64 = Frida.Data.Agent.get_frida_agent_64_so_blob ();
			var emulated_arm = Frida.Data.Agent.get_frida_agent_arm_so_blob ();
			var emulated_arm64 = Frida.Data.Agent.get_frida_agent_arm64_so_blob ();
			agent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),
				new Bytes.static (blob32.data),
				new Bytes.static (blob64.data),
				new AgentResource[] {
					new AgentResource ("frida-agent-arm.so", new Bytes.static (emulated_arm.data), tempdir),
					new AgentResource ("frida-agent-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),
				},
				AgentMode.INSTANCED,
				tempdir);
#endif

		}

		public override async void preload (Cancellable? cancellable) throws Error, IOError {

		}

		public override async void close (Cancellable? cancellable) throws IOError {
			yield base.close (cancellable);


			var linjector = injector as Linjector;

			yield wait_for_uninject (injector, cancellable, () => {
				return linjector.any_still_injected ();
			});

			injector.uninjected.disconnect (on_uninjected);
			yield injector.close (cancellable);

			if (system_session_container != null) {
				yield system_session_container.destroy (cancellable);
				system_session_container = null;
			}

			yield helper.close (cancellable);
			helper.output.disconnect (on_output);

			agent = null;

			tempdir.destroy ();
		}

		protected override async AgentSessionProvider create_system_session_provider (Cancellable? cancellable,
				out DBusConnection connection) throws Error, IOError {
			PipeTransport.set_temp_directory (tempdir.path);

			PathTemplate tpl;
#if HAVE_EMBEDDED_ASSETS
			tpl = agent.get_path_template ();
#else
			tpl = PathTemplate (Config.FRIDA_AGENT_PATH);
#endif
			string path = tpl.expand ((sizeof (void *) == 8) ? "64" : "32");
			system_session_container = yield AgentContainer.create (path, cancellable);

			connection = system_session_container.connection;

			return system_session_container;
		}

		public override async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = FrontmostQueryOptions._deserialize (options);

			return System.get_frontmost_application (opts);
		}

		public override async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = ApplicationQueryOptions._deserialize (options);
			return yield application_enumerator.enumerate_applications (opts);
		}


		public override async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var opts = ProcessQueryOptions._deserialize (options);
			var processes = yield process_enumerator.enumerate_processes (opts);


			return processes;
		}

		public override async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {

			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public override async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable)
				throws Error, IOError {

			return yield helper.spawn (program, options, cancellable);
		}

		protected override bool try_handle_child (HostChildInfo info) {
			return false;
		}

		protected override void notify_child_resumed (uint pid) {
		}

		protected override void notify_child_gating_changed (uint pid, uint subscriber_count) {
		}

		protected override async void prepare_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.prepare_exec_transition (pid, cancellable);
		}

		protected override async void await_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.await_exec_transition (pid, cancellable);
		}

		protected override async void cancel_exec_transition (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.cancel_exec_transition (pid, cancellable);
		}

		protected override bool process_is_alive (uint pid) {
			return Posix.kill ((Posix.pid_t) pid, 0) == 0 || Posix.errno == Posix.EPERM;
		}

		public override async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			yield helper.input (pid, data, cancellable);
		}

		protected override async void perform_resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			yield helper.resume (pid, cancellable);
		}

		public override async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {

			yield helper.kill (pid, cancellable);
		}

		protected override async Future<IOStream> perform_attach_to (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable, out Object? transport) throws Error, IOError {
			PipeTransport.set_temp_directory (tempdir.path);

			var t = new PipeTransport ();

			var stream_request = Pipe.open (t.local_address, cancellable);

			uint id;
			string entrypoint = "frida_agent_main";
			string agent_parameters = make_agent_parameters (t.remote_address, options);
			var linjector = injector as Linjector;
#if HAVE_EMBEDDED_ASSETS
			id = yield linjector.inject_library_resource (pid, agent, entrypoint, agent_parameters, cancellable);
#else
			id = yield linjector.inject_library_file (pid, Config.FRIDA_AGENT_PATH, entrypoint, agent_parameters, cancellable);
#endif
			injectee_by_pid[pid] = id;

			transport = t;

			return stream_request;
		}



		private void on_output (uint pid, int fd, uint8[] data) {
			output (pid, fd, data);
		}
	}

}
