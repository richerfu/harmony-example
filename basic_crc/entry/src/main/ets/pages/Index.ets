import hilog from '@ohos.hilog';
import { crc32 } from 'libcrc32.so'

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
            const ret = crc32('crc32-test', 0);
            hilog.info(0x0000, 'testTag', 'CRC32 = %{public}d', ret);
          })
      }
      .width('100%')
    }
    .height('100%')
  }
}
