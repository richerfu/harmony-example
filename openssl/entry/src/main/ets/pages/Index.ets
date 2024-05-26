import hilog from '@ohos.hilog';
import testNapi from 'libentry.so';
import { fetch } from 'librequest.so';

@Entry
@Component
struct Index {
  build() {
    Row() {
      Column() {
        Text('md5').onClick(() => {
          const ret = testNapi.md5('hello');
          hilog.info(0x0000, 'testTag', `${ret}`);
        })
        Text('request')
          .onClick(() => {
            try {
              const ret = fetch();
              hilog.info(0x0000, 'testTag', `${ret}`);
            }catch (e) {
              const err = e as Error;
              hilog.info(0x0000, 'testTag', `${err.message}`);
            }
          })
      }
      .width('100%')
    }
    .height('100%')
  }
}
