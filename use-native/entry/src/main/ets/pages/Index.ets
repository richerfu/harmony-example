import hilog from '@ohos.hilog';
import {c} from 'libcrc32.so'

@Entry
@Component
struct Index {
  @State message: string = 'Hello World'

  build() {
    Row() {
      Column() {
        Text(this.message)
          .fontSize(50)
          .fontWeight(FontWeight.Bold)
          .onClick(() => {
            const ret = crc32("crc32c - test", 0);
            hilog.info(0x0000, 'testTag', `${ret}`);
          })
      }
      .width('100%')
    }
    .height('100%')
  }
}
