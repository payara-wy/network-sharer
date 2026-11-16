/* Disposable Qt 5 ABI fixture for a local experiment; never bundled in the app.
 * The tested framework does not ship headers. These deliberately oversized opaque
 * objects and QString allocation leaks are confined to this short-lived process;
 * they must not be used in production or assumed compatible with other Qt builds. */
#include <cstdio>
#include <cstring>

class QString {
    void *data;
public:
    static QString fromUtf8_helper(const char *,int);
    ~QString() {}
};
class QVariant {
    alignas(8) unsigned char opaque[64];
public:
    explicit QVariant(const QString &);
    ~QVariant();
};
class QObject;
class QSettings {
    alignas(8) unsigned char opaque[1024];
public:
    enum Format { NativeFormat, IniFormat };
    enum Status { NoError, AccessError, FormatError };
    QSettings(const QString &,Format,QObject *);
    ~QSettings();
    void setValue(const QString &,const QVariant &);
    void sync();
    Status status() const;
};
int main(int argc,char **argv) {
    if (argc!=3) return 2;
    QString path=QString::fromUtf8_helper(argv[1],(int)std::strlen(argv[1]));
    QString key=QString::fromUtf8_helper("vnic0/test",10);
    QString value=QString::fromUtf8_helper(argv[2],(int)std::strlen(argv[2]));
    QSettings settings(path,QSettings::IniFormat,nullptr);
    QVariant variant(value);
    settings.setValue(key,variant);
    settings.sync();
    int status=(int)settings.status();
    std::printf("status=%d\n",status);
    return status;
}
