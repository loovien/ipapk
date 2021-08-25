package ipapk

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"image"
	"image/png"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/andrianbdn/iospng"
	"github.com/shogo82148/androidbinary"
	"github.com/shogo82148/androidbinary/apk"
	"howett.net/plist"
)

var (
	reInfoPlist = regexp.MustCompile(`Payload/[^/]+/Info\.plist`)
	ErrNoIcon   = errors.New("icon not found")
)

const (
	iosExt     = ".ipa"
	androidExt = ".apk"
)

type AppInfo struct {
	Name         string
	BundleId     string
	Version      string
	VersionCode  string
	Build        string
	Icon         image.Image
	Size         int64
	MainActivity string
}

type PkgInfo struct {
	PackageName  string      `json:"packageName"`
	MainActivity string      `json:"mainActivity"`
	Label        string      `json:"label"`
	VersionName  string      `json:"versionName"`
	VersionCode  int         `json:"versionCode"`
	Size         int64       `json:"size"`
	Icon         image.Image `json:"-"`
}

type androidManifest struct {
	Package     string `xml:"package,attr"`
	VersionName string `xml:"versionName,attr"`
	VersionCode string `xml:"versionCode,attr"`
}

type iosPlist struct {
	CFBundleName         string `plist:"CFBundleName"`
	CFBundleDisplayName  string `plist:"CFBundleDisplayName"`
	CFBundleVersion      string `plist:"CFBundleVersion"`
	CFBundleShortVersion string `plist:"CFBundleShortVersionString"`
	CFBundleIdentifier   string `plist:"CFBundleIdentifier"`
}

func NewAPKParser(apkpath string) (*PkgInfo, error) {
	finfo, err := os.Stat(apkpath)
	var info = new(PkgInfo)
	if err != nil {
		return nil, err
	}
	info.Size = finfo.Size()
	pkg, err := apk.OpenFile(apkpath)
	if err != nil {
		return nil, err
	}
	defer pkg.Close()

	info.PackageName = pkg.PackageName()
	info.Label, _ = pkg.Label(nil)
	info.MainActivity, _ = pkg.MainActivity()
	aliases := pkg.Manifest().App.ActivityAliases
	if len(aliases) > 0 {
		for _, activity := range aliases {
			mainAliasActivity, _ := activity.Name.String()
			if len(mainAliasActivity) <= 0 {
				continue
			}
			targetActivity, _ := activity.TargetActivity.String()
			if info.MainActivity != targetActivity {
				continue
			}
			info.MainActivity = mainAliasActivity
		}
	}
	info.Icon, _ = pkg.Icon(nil)
	info.VersionCode = int(pkg.Manifest().VersionCode.MustInt32())
	info.VersionName = pkg.Manifest().VersionName.MustString()
	return info, nil
}

func NewAppParser(name string) (*AppInfo, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	reader, err := zip.NewReader(file, stat.Size())
	if err != nil {
		return nil, err
	}

	var xmlFile, plistFile, iosIconFile *zip.File
	for _, f := range reader.File {
		switch {
		case f.Name == "AndroidManifest.xml":
			xmlFile = f
		case reInfoPlist.MatchString(f.Name):
			plistFile = f
		case strings.Contains(f.Name, "AppIcon60x60"):
			iosIconFile = f
		}
	}

	ext := filepath.Ext(stat.Name())

	if ext == androidExt {
		info, err := parseApkFile(xmlFile)
		icon, label, err := parseApkIconAndLabel(name)
		info.Name = label
		info.Icon = icon
		info.Size = stat.Size()
		return info, err
	}

	if ext == iosExt {
		info, err := parseIpaFile(plistFile)
		icon, err := parseIpaIcon(iosIconFile)
		info.Icon = icon
		info.Size = stat.Size()
		return info, err
	}

	return nil, errors.New("unknown platform")
}

func parseAndroidManifest(xmlFile *zip.File) (*apk.Manifest, error) {
	rc, err := xmlFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	buf, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	xmlContent, err := androidbinary.NewXMLFile(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	manifest := new(apk.Manifest)
	decoder := xml.NewDecoder(xmlContent.Reader())
	if err := decoder.Decode(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func parseApkFile(xmlFile *zip.File) (*AppInfo, error) {
	if xmlFile == nil {
		return nil, errors.New("AndroidManifest.xml not found")
	}

	manifest, err := parseAndroidManifest(xmlFile)
	if err != nil {
		return nil, err
	}

	info := new(AppInfo)
	info.BundleId, _ = manifest.Package.String()
	info.Version, _ = manifest.VersionName.String()
	var code, _ = manifest.VersionCode.Int32()
	info.Build = strconv.Itoa(int(code))
	var mainActivityList []string
	for _, activity := range manifest.App.Activities {

		activityName, _ := activity.Name.String()
		label, _ := activity.Label.String()
		if label == "android.intent.action.MAIN" {
			mainActivityList = append(mainActivityList, activityName)
		}
		for _, filter := range activity.IntentFilters {
			for _, category := range filter.Categories {
				if name, _ := category.Name.String(); name == "android.intent.category.LAUNCHER" {
					activityName, _ := activity.Name.String()
					mainActivityList = append(mainActivityList, activityName)
				}
			}
		}
	}
	if len(mainActivityList) > 0 {
		info.MainActivity = mainActivityList[0]
	}
	return info, nil
}

func parseApkIconAndLabel(name string) (image.Image, string, error) {
	pkg, err := apk.OpenFile(name)
	if err != nil {
		return nil, "", err
	}
	defer pkg.Close()

	icon, _ := pkg.Icon(&androidbinary.ResTableConfig{
		Density: 720,
	})
	if icon == nil {
		return nil, "", ErrNoIcon
	}

	label, _ := pkg.Label(nil)

	return icon, label, nil
}

func parseIpaFile(plistFile *zip.File) (*AppInfo, error) {
	if plistFile == nil {
		return nil, errors.New("info.plist not found")
	}

	rc, err := plistFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	buf, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	p := new(iosPlist)
	decoder := plist.NewDecoder(bytes.NewReader(buf))
	if err := decoder.Decode(p); err != nil {
		return nil, err
	}

	info := new(AppInfo)
	if p.CFBundleDisplayName == "" {
		info.Name = p.CFBundleName
	} else {
		info.Name = p.CFBundleDisplayName
	}
	info.BundleId = p.CFBundleIdentifier
	info.Version = p.CFBundleShortVersion
	info.Build = p.CFBundleVersion

	return info, nil
}

func parseIpaIcon(iconFile *zip.File) (image.Image, error) {
	if iconFile == nil {
		return nil, ErrNoIcon
	}

	rc, err := iconFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var w bytes.Buffer
	iospng.PngRevertOptimization(rc, &w)

	return png.Decode(bytes.NewReader(w.Bytes()))
}
