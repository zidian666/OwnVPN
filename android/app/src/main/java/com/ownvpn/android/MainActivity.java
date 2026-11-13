package com.ownvpn.android;
import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.*;
import android.text.*;
import android.text.method.*;
import android.view.*;
import android.widget.*;
import java.io.File;
import java.util.*;
import java.util.concurrent.*;

public final class MainActivity extends Activity {
    private static final int OVPN = 10, PEM = 11, QR = 12, VPN = 13, DEPENDENCY = 14;
    static final int CONNECT_ID = R.id.connect, USER_ID = R.id.username, PASSWORD_ID = R.id.password,
                     OTP_ID = R.id.otp;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private OwnVpnService service;
    private boolean bound, resumed, previewBusy, preparing;
    private int connectionGeneration;
    private android.content.SharedPreferences preferences;
    private LinearLayout page;
    private Spinner profiles;
    private String[] profileData = new String[0];
    private EditText username, password, otp;
    private CheckBox remember, automatic, reconnect, fallback;
    private TextView status, ip, mark, remaining, diagnostics;
    private Button connect, importButton;
    private ImportWorkspace importing;
    private MissingDependencyException missingDependency;
    private boolean importBusy;
    private String bindingProfile, bindingUser;
    private OwnVpnService.Request pendingRequest;
    private long nextPreview;
    private final ServiceConnection connection = new ServiceConnection() {
        public void onServiceConnected(ComponentName name, IBinder binder) {
            service = ((OwnVpnService.LocalBinder)binder).service();
            refresh();
        }
        public void onServiceDisconnected(ComponentName name) {
            service = null;
            refresh();
        }
    };
    private final Runnable tick = new Runnable() {
        public void run() {
            if (resumed) {
                refresh();
                main.postDelayed(this, 200);
            }
        }
    };
    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
    private TextView text(String value, int size) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(0xff202922);
        return view;
    }
    private LinearLayout row() {
        LinearLayout layout = new LinearLayout(this);
        layout.setGravity(Gravity.CENTER_VERTICAL);
        layout.setOrientation(LinearLayout.HORIZONTAL);
        return layout;
    }
    private void add(View view) {
        page.addView(view, new LinearLayout.LayoutParams(-1, -2));
    }
    private void space(int height) {
        View gap = new View(this);
        page.addView(gap, new LinearLayout.LayoutParams(1, dp(height)));
    }
    private void label(String title) {
        TextView label = text(title, 13);
        label.setTextColor(0xff667068);
        add(label);
    }
    private EditText field(String hint, int type, int id) {
        EditText field = new EditText(this);
        field.setId(id);
        field.setHint(hint);
        field.setTextSize(16);
        field.setSingleLine(true);
        field.setInputType(type);
        field.setPadding(dp(10), 0, dp(10), 0);
        field.setMinHeight(dp(48));
        GradientDrawable background = new GradientDrawable();
        background.setColor(Color.WHITE);
        background.setCornerRadius(dp(7));
        background.setStroke(dp(1), 0xffdce1dc);
        field.setBackground(background);
        return field;
    }
    private CheckBox check(String title, boolean value) {
        CheckBox view = new CheckBox(this);
        view.setText(title);
        view.setTextSize(13);
        view.setChecked(value);
        return view;
    }
    private TextView link(String title, Runnable action) {
        TextView view = text(title, 13);
        view.setTextColor(0xff327560);
        view.setPadding(dp(6), dp(10), dp(6), dp(10));
        view.setOnClickListener(v -> action.run());
        return view;
    }
    private ImageButton copyButton(String description, Runnable action) {
        ImageButton view = new ImageButton(this);
        view.setImageResource(R.drawable.ic_copy);
        view.setContentDescription(description);
        view.setTooltipText(description);
        view.setBackgroundColor(Color.TRANSPARENT);
        view.setPadding(dp(12), dp(12), dp(12), dp(12));
        view.setOnClickListener(v -> action.run());
        return view;
    }
    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        preferences = getSharedPreferences("ui", MODE_PRIVATE);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(0xfff7f8f6);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            } else
                view.setPadding(0, insets.getSystemWindowInsetTop(), 0, insets.getSystemWindowInsetBottom());
            return insets;
        });
        page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(24), dp(18), dp(24), dp(20));
        scroll.addView(page);
        setContentView(scroll);
        TextView title = text("OwnVPN", 25);
        title.setTypeface(null, Typeface.BOLD);
        add(title);
        space(18);
        LinearLayout stateRow = row();
        mark = text("O", 32);
        mark.setTypeface(null, Typeface.BOLD);
        stateRow.addView(mark, new LinearLayout.LayoutParams(dp(42), dp(52)));
        status = text("未连接", 23);
        stateRow.addView(status, new LinearLayout.LayoutParams(0, -2, 1));
        ip = text("", 14);
        ip.setTextColor(0xff327560);
        ip.setOnClickListener(v -> copy("VPN 地址", ip.getText().toString()));
        stateRow.addView(ip);
        add(stateRow);
        space(12);
        label("连接配置");
        LinearLayout profileRow = row();
        profiles = new Spinner(this);
        profileRow.addView(profiles, new LinearLayout.LayoutParams(0, dp(48), 1));
        importButton = new Button(this);
        importButton.setText("导入");
        importButton.setOnClickListener(v -> pick(OVPN, "*/*"));
        profileRow.addView(importButton);
        add(profileRow);
        space(12);
        label("账号");
        username = field("公司 VPN 账号",
                         android.text.InputType.TYPE_CLASS_TEXT |
                             android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
                         USER_ID);
        add(username);
        space(12);
        label("密码");
        LinearLayout passRow = row();
        password = field("VPN 密码",
                         android.text.InputType.TYPE_CLASS_TEXT |
                             android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD,
                         PASSWORD_ID);
        passRow.addView(password, new LinearLayout.LayoutParams(0, dp(48), 1));
        passRow.addView(copyButton("复制密码", () -> copy("密码", password.getText().toString())),
                        new LinearLayout.LayoutParams(dp(44), dp(44)));
        add(passRow);
        LinearLayout passOptions = row();
        remember = check("记住密码", false);
        passOptions.addView(remember);
        CheckBox show = check("显示密码", false);
        show.setOnCheckedChangeListener((button, checked) -> {
            password.setTransformationMethod(checked ? HideReturnsTransformationMethod.getInstance()
                                                     : PasswordTransformationMethod.getInstance());
            password.setSelection(password.length());
        });
        passOptions.addView(show);
        TextView instant = link("复制即时密码", () -> copyOtp(true));
        instant.setTooltipText("复制密码与当前六位验证码的拼接结果，用于其他 VPN 登录窗口");
        passOptions.addView(instant);
        add(passOptions);
        space(10);
        LinearLayout otpTitle = row();
        otpTitle.addView(text("验证码", 13), new LinearLayout.LayoutParams(0, -2, 1));
        automatic = check("", preferences.getBoolean("automatic", false));
        automatic.setContentDescription("自动生成验证码");
        automatic.setOnCheckedChangeListener((button, value) -> {
            preferences.edit().putBoolean("automatic", value).apply();
            applyOtpMode();
        });
        otpTitle.addView(automatic);
        otpTitle.addView(link("自动生成", this::bindingDialog));
        add(otpTitle);
        LinearLayout otpRow = row();
        otp = field("6 位动态验证码", android.text.InputType.TYPE_CLASS_NUMBER, OTP_ID);
        otp.setFilters(new InputFilter[] {new InputFilter.LengthFilter(6)});
        otpRow.addView(otp, new LinearLayout.LayoutParams(0, dp(48), 1));
        otpRow.addView(copyButton("复制验证码", () -> copyOtp(false)),
                       new LinearLayout.LayoutParams(dp(44), dp(44)));
        add(otpRow);
        remaining = text("", 12);
        remaining.setTextColor(0xff667068);
        add(remaining);
        space(6);
        LinearLayout connectionOptions = row();
        reconnect = check("自动重连", preferences.getBoolean("reconnect", true));
        fallback = check("尝试绕过DNS", preferences.getBoolean("fallback", true));
        fallback.setTooltipText("正常解析域名；仅在 DNS 失败时尝试上次保存的 IP，解析成功会更新缓存");
        connectionOptions.addView(reconnect);
        connectionOptions.addView(fallback);
        add(connectionOptions);
        space(12);
        connect = new Button(this);
        connect.setId(CONNECT_ID);
        connect.setText("连接 VPN");
        connect.setMinHeight(dp(52));
        connect.setTextColor(Color.WHITE);
        GradientDrawable button = new GradientDrawable();
        button.setColor(0xff327560);
        button.setCornerRadius(dp(8));
        connect.setBackground(button);
        connect.setOnClickListener(v -> connectOrStop());
        add(connect);
        space(12);
        TextView diagnosticButton =
            link("查看诊断",
                 ()
                     -> diagnostics.setVisibility(diagnostics.getVisibility() == View.GONE ? View.VISIBLE
                                                                                           : View.GONE));
        add(diagnosticButton);
        diagnostics = text("暂无连接记录", 12);
        diagnostics.setTextIsSelectable(true);
        diagnostics.setVisibility(View.GONE);
        add(diagnostics);
        TextView usage = text(
            "1 从邮件下载 users.pem 和原始 ZIP 配置包\n2 导入 ZIP，选择配置后再选择 users.pem。单独导入 " +
            ".ovpn 时，按提示补齐包内的 .key 和 .crt 文件\n3 从 "
                + "https://y2m.knownsec.com/auth/otp/login 获取二维码\n4 "
                + "填写账号并导入二维码，勾选自动生成\n5 选择自动重连，连接 VPN\n\n首次使用公司 Wi-Fi 若 "
                + "DNS 解析失败，请先通过其他网络成功连接，保存 IP 后再切回公司 Wi-Fi。",
            13);
        android.text.util.Linkify.addLinks(usage, android.text.util.Linkify.WEB_URLS);
        usage.setMovementMethod(LinkMovementMethod.getInstance());
        usage.setVisibility(View.GONE);
        add(link("使用说明",
                 () -> usage.setVisibility(usage.getVisibility() == View.GONE ? View.VISIBLE : View.GONE)));
        add(usage);
        space(10);
        TextView version = text("0.5.0-alpha.2", 11);
        version.setTextColor(0xff8b938d);
        version.setTooltipText("查看开源许可");
        version.setOnClickListener(v -> licenses());
        add(version);
        profiles.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                loadAccount();
            }
            public void onNothingSelected(AdapterView<?> parent) {}
        });
        applyOtpMode();
        reloadProfiles(preferences.getString("profile", ""));
        bound = bindService(new Intent(this, OwnVpnService.class).setAction("local"), connection,
                            BIND_AUTO_CREATE);
    }
    private String selected() {
        int index = profiles.getSelectedItemPosition() * 2;
        return index >= 0 && index < profileData.length ? profileData[index] : "";
    }
    private void reloadProfiles(String choose) {
        profileData = NativeBridge.profiles();
        List<String> names = new ArrayList<>();
        int selection = 0;
        for (int i = 0; i < profileData.length; i += 2) {
            names.add(profileData[i + 1]);
            if (profileData[i].equals(choose))
                selection = i / 2;
        }
        if (names.isEmpty())
            names.add("请先导入配置");
        profiles.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, names));
        profiles.setSelection(selection);
    }
    private void loadAccount() {
        String profile = selected();
        if (profile.isEmpty())
            return;
        preferences.edit().putString("profile", profile).apply();
        boolean saved = preferences.getBoolean("remember." + profile, false);
        remember.setChecked(saved);
        io.execute(() -> {
            try {
                String user = NativeBridge.readSecret(profile, "ui.username"),
                       pass = saved ? NativeBridge.readSecret(profile, "ui.password") : "";
                main.post(() -> {
                    if (profile.equals(selected())) {
                        username.setText(user);
                        password.setText(pass);
                    }
                });
            } catch (RuntimeException error) {
                main.post(() -> message(error.getMessage()));
            }
        });
    }
    private void applyOtpMode() {
        if (otp == null)
            return;
        otp.setKeyListener(
            automatic.isChecked() ? null : android.text.method.DigitsKeyListener.getInstance("0123456789"));
        otp.setFocusableInTouchMode(!automatic.isChecked());
        otp.setText("");
        remaining.setText(automatic.isChecked() ? "等待验证码绑定" : "");
        nextPreview = 0;
    }
    private void refresh() {
        OwnVpnService.Snapshot state = service == null ? null : service.snapshot();
        boolean active = preparing || state != null && state.active;
        String message = preparing ? "正在准备连接" : state == null ? "未连接" : state.message;
        setText(status, message);
        setText(ip, state == null ? "" : state.ip);
        mark.setTextColor(state != null && "CONNECTED".equals(state.state) ? 0xff327560 : 0xffa4aca5);
        setText(diagnostics, state == null || state.diagnostic.isEmpty() ? "暂无连接记录" : state.diagnostic);
        connect.setEnabled(service != null && (state == null || !"STOPPING".equals(state.state)));
        setText(connect, preparing ? "取消连接" : active ? "断开连接" : "连接 VPN");
        profiles.setEnabled(!active);
        importButton.setEnabled(!active && !importBusy);
        username.setEnabled(!active);
        password.setEnabled(!active);
        automatic.setEnabled(!active);
        remember.setEnabled(!active);
        reconnect.setEnabled(!active);
        fallback.setEnabled(!active);
        if (automatic.isChecked() && !previewBusy && SystemClock.elapsedRealtime() >= nextPreview &&
            !selected().isEmpty() && username.length() > 0) {
            nextPreview = SystemClock.elapsedRealtime() + 400;
            previewBusy = true;
            String profile = selected(), user = username.getText().toString();
            io.execute(() -> {
                String value = "";
                try {
                    value = NativeBridge.totp(profile, user);
                } catch (RuntimeException ignored) {
                }
                final String generated = value;
                main.post(() -> {
                    previewBusy = false;
                    if (!automatic.isChecked() || !profile.equals(selected()) ||
                        !user.equals(username.getText().toString()))
                        return;
                    if (generated.isEmpty()) {
                        setText(otp, "");
                        setText(remaining, "请点击“自动生成”导入二维码或密钥");
                    } else {
                        String[] parts = generated.split(" ");
                        setText(otp, parts[0]);
                        setText(remaining, parts[1] + " 秒后更新");
                    }
                });
            });
        }
    }
    private void setText(TextView view, String value) {
        if (!view.getText().toString().equals(value))
            view.setText(value);
    }
    private void connectOrStop() {
        if (preparing) {
            preparing = false;
            connectionGeneration++;
            refresh();
            return;
        }
        if (service == null)
            return;
        if (service.snapshot().active) {
            service.disconnect();
            return;
        }
        String profile = selected(), user = username.getText().toString().trim(),
               pass = password.getText().toString(), code = otp.getText().toString();
        if (profile.isEmpty() || user.isEmpty() || pass.isEmpty() || !code.matches("[0-9]{6}")) {
            message("请导入配置并填写账号、密码和 6 位验证码");
            return;
        }
        OwnVpnService.Request request = new OwnVpnService.Request(
            profile, user, pass, code, automatic.isChecked(), reconnect.isChecked(), fallback.isChecked());
        boolean save = remember.isChecked();
        preparing = true;
        int generation = ++connectionGeneration;
        refresh();
        preferences.edit()
            .putBoolean("remember." + profile, save)
            .putBoolean("reconnect", request.reconnect)
            .putBoolean("fallback", request.fallback)
            .apply();
        io.execute(() -> {
            try {
                NativeBridge.writeSecret(profile, "ui.username", user);
                NativeBridge.writeSecret(profile, "ui.password", save ? pass : "");
                main.post(() -> {
                    if (generation != connectionGeneration || isFinishing())
                        return;
                    preparing = false;
                    pendingRequest = request;
                    Intent permission = VpnService.prepare(this);
                    if (permission != null)
                        startActivityForResult(permission, VPN);
                    else
                        startVpn();
                });
            } catch (RuntimeException error) {
                main.post(() -> {
                    preparing = false;
                    message(error.getMessage());
                });
            }
        });
    }
    private void startVpn() {
        OwnVpnService.Request request = pendingRequest;
        pendingRequest = null;
        if (request == null || service == null)
            return;
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
                android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[] {android.Manifest.permission.POST_NOTIFICATIONS}, 20);
        startForegroundService(new Intent(this, OwnVpnService.class).setAction(OwnVpnService.START));
        service.connect(request);
        refresh();
    }
    private void pick(int code, String type) {
        startActivityForResult(
            new Intent(Intent.ACTION_OPEN_DOCUMENT).setType(type).addCategory(Intent.CATEGORY_OPENABLE),
            code);
    }
    private void bindingDialog() {
        if (selected().isEmpty() || username.length() == 0) {
            message("请先选择配置并填写账号");
            return;
        }
        bindingProfile = selected();
        bindingUser = username.getText().toString().trim();
        new AlertDialog.Builder(this)
            .setTitle("绑定验证码")
            .setItems(new String[] {"导入二维码图片", "输入绑定密钥或 otpauth URI"},
                      (dialog, index) -> {
                          if (index == 0)
                              pick(QR, "image/*");
                          else {
                              EditText input = field("绑定密钥或 otpauth://…",
                                                     android.text.InputType.TYPE_CLASS_TEXT |
                                                         android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD,
                                                     View.NO_ID);
                              input.setSingleLine(false);
                              new AlertDialog.Builder(this)
                                  .setTitle("绑定资料")
                                  .setView(input)
                                  .setPositiveButton("绑定", (d, w) -> bindValue(input.getText().toString()))
                                  .setNegativeButton("取消", null)
                                  .show();
                          }
                      })
            .show();
    }
    private void bindValue(String input) {
        String profile = bindingProfile, user = bindingUser;
        io.execute(() -> {
            try {
                NativeBridge.bindTotp(profile, user, input);
                main.post(() -> {
                    automatic.setChecked(true);
                    nextPreview = 0;
                    message("验证码已绑定");
                });
            } catch (RuntimeException error) {
                main.post(() -> message(error.getMessage()));
            }
        });
    }
    private void closeImport() {
        ImportWorkspace old = importing;
        importing = null;
        missingDependency = null;
        importBusy = false;
        if (old != null)
            io.execute(() -> {
                try {
                    old.close();
                } catch (java.io.IOException ignored) {
                }
            });
    }
    private void importError(Exception error) {
        main.post(() -> {
            if (isDestroyed())
                return;
            closeImport();
            message(error.getMessage());
        });
    }
    private void prepareImport(Uri uri, String name) {
        closeImport();
        importBusy = true;
        refresh();
        io.execute(() -> {
            ImportWorkspace workspace = null;
            try {
                workspace = new ImportWorkspace(getCacheDir());
                try (java.io.InputStream input = DocumentImport.open(this, uri)) {
                    if (name.toLowerCase(Locale.ROOT).endsWith(".zip"))
                        workspace.archive(input);
                    else
                        workspace.document(name, input);
                }
                ImportWorkspace ready = workspace;
                main.post(() -> {
                    if (isDestroyed()) {
                        try {
                            ready.close();
                        } catch (java.io.IOException ignored) {
                        }
                        return;
                    }
                    importing = ready;
                    String[] names = ready.configurations();
                    if (names.length == 1) {
                        ready.choose(0);
                        askPem();
                    } else
                        new AlertDialog.Builder(this)
                            .setTitle("选择 VPN 配置")
                            .setItems(names,
                                      (dialog, index) -> {
                                          ready.choose(index);
                                          askPem();
                                      })
                            .setNegativeButton("取消", (dialog, which) -> closeImport())
                            .setOnCancelListener(dialog -> closeImport())
                            .show();
                });
            } catch (Exception error) {
                if (workspace != null)
                    try {
                        workspace.close();
                    } catch (java.io.IOException ignored) {
                    }
                importError(error);
            }
        });
    }
    private void askPem() {
        new AlertDialog.Builder(this)
            .setTitle("选择 users.pem")
            .setMessage("选择客户端证书和私钥文件 users.pem。配置已包含证书时可以跳过。")
            .setPositiveButton("选择 PEM", (d, w) -> pick(PEM, "*/*"))
            .setNeutralButton("跳过", (d, w) -> attemptImport())
            .setNegativeButton("取消", (d, w) -> closeImport())
            .setOnCancelListener(d -> closeImport())
            .show();
    }
    private void attemptImport() {
        ImportWorkspace workspace = importing;
        if (workspace == null)
            return;
        io.execute(() -> {
            try {
                String id = NativeBridge.importProfileFiles(
                    workspace.configurationPath(), workspace.pemPath(), workspace.dependencyOptions(),
                    workspace.dependencyPaths(), workspace.referenceRoot());
                try {
                    workspace.close();
                } catch (java.io.IOException ignored) {
                }
                main.post(() -> {
                    if (isDestroyed())
                        return;
                    importing = null;
                    missingDependency = null;
                    importBusy = false;
                    reloadProfiles(id);
                    message("配置已导入");
                });
            } catch (MissingDependencyException error) {
                main.post(() -> {
                    if (isDestroyed())
                        return;
                    missingDependency = error;
                    String detail =
                        "请选择配置引用的文件：\n" + error.reference + "\n\n依赖类型：" + error.option;
                    if (error.option.equals("tls-auth") || error.option.equals("tls-crypt"))
                        detail += "\n这是 TLS 认证密钥，需要选择配置包内对应的 .key 文件。";
                    new AlertDialog.Builder(this)
                        .setTitle("补齐依赖文件")
                        .setMessage(detail)
                        .setPositiveButton("选择文件", (d, w) -> pick(DEPENDENCY, "*/*"))
                        .setNegativeButton("取消", (d, w) -> closeImport())
                        .setOnCancelListener(d -> closeImport())
                        .show();
                });
            } catch (Exception error) {
                importError(error);
            }
        });
    }
    private void importFile(Uri uri, boolean dependency) {
        ImportWorkspace workspace = importing;
        MissingDependencyException requested = missingDependency;
        if (workspace == null || dependency && requested == null) {
            message("导入会话已结束，请重新选择配置");
            return;
        }
        io.execute(() -> {
            try (java.io.InputStream input = DocumentImport.open(this, uri)) {
                if (dependency)
                    workspace.dependency(requested.option, input);
                else
                    workspace.pem(input);
                main.post(() -> {
                    if (!isDestroyed())
                        attemptImport();
                });
            } catch (Exception error) {
                importError(error);
            }
        });
    }
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN) {
            if (resultCode == RESULT_OK)
                startVpn();
            else {
                pendingRequest = null;
                message("VPN 授权已取消");
            }
            return;
        }
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            if (requestCode == OVPN || requestCode == PEM || requestCode == DEPENDENCY)
                closeImport();
            return;
        }
        Uri uri = data.getData();
        if (requestCode == OVPN) {
            String name = DocumentImport.displayName(this, uri), lower = name.toLowerCase(Locale.ROOT);
            if (!lower.endsWith(".ovpn") && !lower.endsWith(".zip")) {
                message("请选择 .ovpn 配置或 .zip 配置包");
                return;
            }
            prepareImport(uri, name);
        } else if (requestCode == PEM)
            importFile(uri, false);
        else if (requestCode == DEPENDENCY)
            importFile(uri, true);
        else if (requestCode == QR)
            io.execute(() -> {
                try {
                    String value = DocumentImport.qr(this, uri);
                    main.post(() -> bindValue(value));
                } catch (Exception error) {
                    main.post(() -> message(error.getMessage()));
                }
            });
    }
    private void copy(String label, String value) {
        if (value.isEmpty()) {
            message("没有可复制的内容");
            return;
        }
        if ("即时密码".equals(label) && !otp.getText().toString().matches("[0-9]{6}")) {
            message("请先生成或填写验证码");
            return;
        }
        ClipData clip = ClipData.newPlainText(label, value);
        PersistableBundle extras = new PersistableBundle();
        extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
        clip.getDescription().setExtras(extras);
        getSystemService(android.content.ClipboardManager.class).setPrimaryClip(clip);
    }
    private void copyOtp(boolean combined) {
        String pass = password.getText().toString();
        if (combined && pass.isEmpty()) {
            message("请先填写密码");
            return;
        }
        if (!automatic.isChecked()) {
            String code = otp.getText().toString();
            if (!code.matches("[0-9]{6}")) {
                message("请填写 6 位验证码");
                return;
            }
            copy(combined ? "即时密码" : "验证码", (combined ? pass : "") + code);
            return;
        }
        String profile = selected(), user = username.getText().toString();
        io.execute(() -> {
            try {
                String value = NativeBridge.totp(profile, user);
                String code = value.split(" ")[0];
                main.post(() -> {
                    if (!isFinishing() && profile.equals(selected()) &&
                        user.equals(username.getText().toString())) {
                        if (!code.matches("[0-9]{6}")) {
                            message("请先绑定验证码");
                            return;
                        }
                        setText(otp, code);
                        copy(combined ? "即时密码" : "验证码", (combined ? pass : "") + code);
                    }
                });
            } catch (RuntimeException error) {
                main.post(() -> message("请先绑定验证码"));
            }
        });
    }
    private void licenses() {
        try {
            String[] names = getAssets().list("licenses");
            if (names == null)
                return;
            new AlertDialog.Builder(this)
                .setTitle("开源许可")
                .setItems(names, (dialog, index) -> io.execute(() -> {
                    try (java.io.InputStream input = getAssets().open("licenses/" + names[index]);
                         java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream()) {
                        byte[] bytes = new byte[4096];
                        int n;
                        while ((n = input.read(bytes)) != -1)
                            buffer.write(bytes, 0, n);
                        String content = buffer.toString("UTF-8");
                        main.post(() -> {
                            TextView view = text(content, 12);
                            view.setPadding(dp(16), dp(12), dp(16), dp(12));
                            ScrollView scroll = new ScrollView(this);
                            scroll.addView(view);
                            new AlertDialog.Builder(this)
                                .setTitle(names[index])
                                .setView(scroll)
                                .setPositiveButton("关闭", null)
                                .show();
                        });
                    } catch (Exception error) {
                        main.post(() -> message("无法读取许可文件"));
                    }
                }))
                .show();
        } catch (Exception error) {
            message("无法读取许可文件");
        }
    }
    private void message(String text) {
        if (!isFinishing())
            Toast.makeText(this, text == null ? "操作失败" : text, Toast.LENGTH_LONG).show();
    }
    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        main.post(tick);
    }
    @Override
    protected void onPause() {
        resumed = false;
        main.removeCallbacks(tick);
        super.onPause();
    }
    @Override
    protected void onDestroy() {
        connectionGeneration++;
        resumed = false;
        main.removeCallbacksAndMessages(null);
        if (bound)
            unbindService(connection);
        closeImport();
        io.shutdown();
        super.onDestroy();
    }
}
